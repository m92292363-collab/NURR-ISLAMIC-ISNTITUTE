// netlify/functions/api.js
//
// Single consolidated API for Imam Malick Islamic Institute.
//
// Routing: the frontend calls /api/<route-name> (e.g. /api/admin-login).
// netlify.toml rewrites /api/* -> /.netlify/functions/api/:splat, and this
// single function reads the last path segment to decide which piece of
// logic to run.
//
// SECURITY:
//  - admin-login / student-login return a signed token (HMAC-SHA256 using the
//    AUTH_SECRET env var). Every other route needs "Authorization: Bearer <token>".
//  - Admin-only routes reject student tokens. Student routes only allow the
//    student's OWN data (admins can open any student).
//  - Passwords are hashed with scrypt. Old plain-text passwords still work and
//    are upgraded to a hash automatically (on login, and in batches by init-db).
//  - Server-side lockout: 5 wrong passwords -> account locked for 15 minutes.
//  - init-db only works with the INIT_SECRET env var (no hard-coded fallback).
//  - The database is updated AUTOMATICALLY when new code is deployed (ensureSchema),
//    so running the init-db link after an update is no longer required.
//
// FINANCE:
//  - fee_payments is NOT linked to students with a cascade: deleting a student
//    keeps every payment. Payments are never hard-deleted, only VOIDED with a reason.
//  - student_enrollments stores which grade/class each student was in for each
//    academic year. Expected fees use the grade the student was in THAT year,
//    so promoting students never changes old fee balances.
//
// RECORDS (every year is kept):
//  - Students are NEVER hard-deleted. "archive-student" hides them from the
//    active roster and blocks login; results, remarks, enrollments and
//    payments for every year stay on record. They can be restored any time.
//  - The database itself refuses to delete a student who has results/remarks
//    (foreign keys changed from CASCADE to RESTRICT).
//  - Any mark that is overwritten or deleted is copied to results_archive first.
//  - Marks entered for a past year use the grade the student was in THAT year.
//  - "student-history" returns every year on record for one student.
//  - "get-enrollments" lists every student in every year (for Browse by Year).
//
// TEACHERS:
//  - Admin creates teacher accounts and assigns them class + subjects per year.
//  - Teachers log in (teacher-login) and can ONLY enter scores for their own
//    assigned subject/class, and mark TODAY's attendance for their classes.
//  - Every score records who entered it (entered_by / entered_at).
//  - Admin can view/fix attendance for any date and print attendance reports.
//
// TEACHER ACCESS LINKS:
//  - Teachers can only log in through a personal access link the admin creates,
//    valid until a date the admin chooses. The admin can cancel a link any time.
//  - Every teacher request checks the link is still valid, so an expired or
//    cancelled link stops working immediately, even mid-session.
//  - Only a hash of the link key is stored in the database.
//
// WEBSITE CONTENT (CMS):
//  - Admin uploads slideshow pictures and news posts; the public site loads
//    them from "site-content". Images are stored in the database ("media")
//    and served by "image?id=" with long browser caching.
//  - Nothing is deleted: removed slides are kept (can be restored), news posts
//    can only be hidden, and EVERY create/edit/hide is saved in news_history.

import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
};

function json(body, statusCode = 200) {
  return { statusCode, headers: HEADERS, body: JSON.stringify(body) };
}

function preflight() {
  return { statusCode: 204, headers: HEADERS, body: '' };
}

function getDb() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL environment variable is not set');
  }
  return neon(process.env.DATABASE_URL);
}

function getRoute(event) {
  const path = event.path || '';
  const segments = path.split('/').filter(Boolean);
  return segments[segments.length - 1] || '';
}

// ---------------------------------------------------------------------------
// Security helpers: tokens, password hashing, lockout
// ---------------------------------------------------------------------------

const ADMIN_TOKEN_HOURS = 12;
const STUDENT_TOKEN_HOURS = 8;
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

function authSecret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 32) {
    throw new Error('AUTH_SECRET environment variable is missing or shorter than 32 characters');
  }
  return s;
}

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', authSecret()).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', authSecret()).update(body).digest('base64url');
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getAuth(event) {
  const h = event.headers || {};
  const raw = h.authorization || h.Authorization || '';
  const m = raw.match(/^Bearer\s+(.+)$/i);
  return m ? verifyToken(m[1].trim()) : null;
}

function canAccessStudent(auth, studentId) {
  return !!auth && (auth.role === 'admin' || (auth.role === 'student' && auth.sub === studentId));
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pw), salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

// Returns { ok, needsRehash }. Accepts legacy plain-text passwords so old
// accounts keep working; those get re-hashed after a successful login.
function checkPassword(pw, stored) {
  if (!stored) return { ok: false, needsRehash: false };
  if (String(stored).startsWith('scrypt$')) {
    const [, saltHex, hashHex] = String(stored).split('$');
    const expected = Buffer.from(hashHex || '', 'hex');
    if (!expected.length) return { ok: false, needsRehash: false };
    const actual = crypto.scryptSync(String(pw), Buffer.from(saltHex, 'hex'), expected.length);
    return { ok: crypto.timingSafeEqual(actual, expected), needsRehash: false };
  }
  const a = Buffer.from(String(pw));
  const b = Buffer.from(String(stored));
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  return { ok, needsRehash: ok };
}

// Returns minutes left on a lock, or 0 if not locked.
async function lockMinutesLeft(sql, key) {
  const rows = await sql`SELECT locked_until FROM login_attempts WHERE key = ${key}`;
  if (rows.length && rows[0].locked_until) {
    const ms = new Date(rows[0].locked_until).getTime() - Date.now();
    if (ms > 0) return Math.ceil(ms / 60000);
  }
  return 0;
}

async function recordFail(sql, key) {
  const rows = await sql`
    INSERT INTO login_attempts (key, fails) VALUES (${key}, 1)
    ON CONFLICT (key) DO UPDATE SET fails = login_attempts.fails + 1
    RETURNING fails
  `;
  if (rows[0].fails >= MAX_FAILS) {
    await sql`
      UPDATE login_attempts
      SET fails = 0, locked_until = NOW() + make_interval(mins => ${LOCK_MINUTES}::int)
      WHERE key = ${key}
    `;
  }
}

async function clearFails(sql, key) {
  await sql`DELETE FROM login_attempts WHERE key = ${key}`;
}

// ---------------------------------------------------------------------------
// Enrollment helper: records (student, current academic year) -> grade/class.
// Safe to call any time; does nothing if the student has no year/grade yet.
// ---------------------------------------------------------------------------
async function syncEnrollment(sql, studentId) {
  await sql`
    INSERT INTO student_enrollments (student_id, academic_year, grade_level, class_name, full_name)
    SELECT student_id, academic_year, grade_level, class_name, full_name
    FROM students
    WHERE student_id = ${studentId}
      AND academic_year IS NOT NULL
      AND grade_level IS NOT NULL
    ON CONFLICT (student_id, academic_year) DO UPDATE SET
      grade_level = EXCLUDED.grade_level,
      class_name  = EXCLUDED.class_name,
      full_name   = EXCLUDED.full_name
  `;
}

async function loadStudentProfile(sql, studentId) {
  const rows = await sql`
    SELECT
      student_id, full_name, password_hash, grade_level, class_name,
      academic_year, status,
      date_of_birth, gender, student_phone, guardian_name, guardian_phone,
      address, profile_photo, upload_blocked,
      place_of_birth, mother_name, mother_phone, father_name, father_phone
    FROM students
    WHERE student_id = ${studentId}
    LIMIT 1
  `;
  return rows[0] || null;
}

// ---------------------------------------------------------------------------
// admin-login  (POST)  — public
// ---------------------------------------------------------------------------
async function adminLogin(sql, event) {
  try {
    const { adminId, password } = JSON.parse(event.body || '{}');
    if (!adminId || !password) {
      return json({ error: 'Admin ID and password are required' }, 400);
    }
    const key = 'admin:' + String(adminId).toLowerCase();
    const mins = await lockMinutesLeft(sql, key);
    if (mins) {
      return json({ success: false, error: `Too many failed attempts. Try again in ${mins} minute(s).` }, 429);
    }
    const rows = await sql`SELECT id, username, password FROM admins WHERE username = ${adminId} LIMIT 1`;
    const check = rows.length ? checkPassword(password, rows[0].password) : { ok: false };
    if (!check.ok) {
      await recordFail(sql, key);
      return json({ success: false, error: 'Incorrect Admin ID or password' }, 401);
    }
    await clearFails(sql, key);
    if (check.needsRehash) {
      await sql`UPDATE admins SET password = ${hashPassword(password)} WHERE id = ${rows[0].id}`;
    }
    const token = signToken({ role: 'admin', sub: rows[0].username, exp: Date.now() + ADMIN_TOKEN_HOURS * 3600 * 1000 });
    return json({ success: true, token });
  } catch (err) {
    console.error('admin-login error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

async function ownerLogin(sql, event) {
  try {
    const { username, password } = JSON.parse(event.body || '{}');
    if (!username || !password) return json({ error: 'Username and password are required' }, 400);
    const key = 'owner:' + String(username).toLowerCase();
    const mins = await lockMinutesLeft(sql, key);
    if (mins) return json({ success: false, error: `Too many failed attempts. Try again in ${mins} minute(s).` }, 429);
    const rows = await sql`SELECT id, username, password FROM owners WHERE username = ${username} LIMIT 1`;
    const check = rows.length ? checkPassword(password, rows[0].password) : { ok: false };
    if (!check.ok) { await recordFail(sql, key); return json({ success: false, error: 'Incorrect username or password' }, 401); }
    await clearFails(sql, key);
    const token = signToken({ role: 'owner', sub: rows[0].username, exp: Date.now() + 12 * 3600 * 1000 });
    return json({ success: true, token });
  } catch (err) { console.error('owner-login error:', err); return json({ success: false, error: 'Server error: ' + err.message }, 500); }
}
async function ownerSetup(sql, event) {
  try {
    const { secret, username, password } = event.queryStringParameters || {};
    if (!process.env.INIT_SECRET || secret !== process.env.INIT_SECRET) return json({ error: 'Forbidden' }, 403);
    if (!username || !password || String(password).length < 8) return json({ error: 'username and password (min 8 chars) are required' }, 400);
    await sql`INSERT INTO owners (username, password) VALUES (${username}, ${hashPassword(password)}) ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password`;
    return json({ success: true, message: `Owner "${username}" is ready. Log in at /owner.` });
  } catch (err) { console.error('owner-setup error:', err); return json({ success: false, error: 'Server error: ' + err.message }, 500); }
}
async function getActivityLog(sql, event) {
  try {
    const { role, category, actor, q, from, to, cursor, limit } = event.queryStringParameters || {};
    const lim = Math.min(200, Math.max(10, parseInt(limit) || 60));
    const params = [], cond = [];
    if (role) { params.push(role); cond.push(`actor_role = $${params.length}`); }
    if (category) { params.push(category); cond.push(`category = $${params.length}`); }
    if (actor) { params.push('%' + actor + '%'); cond.push(`actor_name ILIKE $${params.length}`); }
    if (q) { params.push('%' + q + '%'); cond.push(`(detail ILIKE $${params.length} OR action ILIKE $${params.length} OR target ILIKE $${params.length})`); }
    if (from && /^\d{4}-\d{2}-\d{2}$/.test(from)) { params.push(from); cond.push(`at >= $${params.length}::date`); }
    if (to && /^\d{4}-\d{2}-\d{2}$/.test(to)) { params.push(to); cond.push(`at < ($${params.length}::date + 1)`); }
    if (cursor && /^\d+$/.test(cursor)) { params.push(cursor); cond.push(`id < $${params.length}`); }
    const where = cond.length ? 'WHERE ' + cond.join(' AND ') : '';
    params.push(lim + 1);
    const rows = await sql(`SELECT id, to_char(at, 'DD/MM/YYYY HH24:MI:SS') AS when, actor_role, actor_name, action, category, detail, target, ok, ip, device, location
      FROM activity_log ${where} ORDER BY id DESC LIMIT $${params.length}`, params);
    const more = rows.length > lim;
    return json({ success: true, rows: rows.slice(0, lim), nextCursor: more ? rows[lim - 1].id : null });
  } catch (err) { console.error('activity-log error:', err); return json({ success: false, error: 'Server error: ' + err.message }, 500); }
}
async function getActivitySummary(sql, event) {
  try {
    const days = Math.min(90, Math.max(1, parseInt((event.queryStringParameters || {}).days) || 7));
    const since = `NOW() - INTERVAL '${days} days'`;
    const totals = await sql(`SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE category='login')::int AS logins,
      COUNT(*) FILTER (WHERE ok = FALSE)::int AS failed, COUNT(*) FILTER (WHERE action LIKE 'VOIDED%')::int AS voids
      FROM activity_log WHERE at >= ${since}`);
    const byActor = await sql(`SELECT actor_name, COUNT(*)::int AS n FROM activity_log WHERE at >= ${since} AND actor_name IS NOT NULL GROUP BY actor_name ORDER BY n DESC LIMIT 8`);
    const recentLogins = await sql(`SELECT to_char(at,'DD/MM HH24:MI') AS when, actor_name, ok, ip, device, location FROM activity_log WHERE category='login' ORDER BY id DESC LIMIT 8`);
    return json({ success: true, days, totals: totals[0], byActor, recentLogins });
  } catch (err) { console.error('activity-summary error:', err); return json({ success: false, error: 'Server error: ' + err.message }, 500); }
}
async function adminView() { return json({ success: true }); }

// sds-admin (POST) — SDS Oversight Console manages the admin account here.
// Requires BOTH the feed key (X-SDS-Key) AND the SDS_ALLOW_ADMIN env var set to
// 'yes' on this school, so remote management is strictly opt-in per school.
// Everything it does is written to the activity log and is visible to the admin.
async function sdsAdmin(sql, event) {
  try {
    const configured = process.env.SDS_FEED_KEY;
    if (!configured) return json({ error: 'Feed not enabled on this site' }, 403);
    const sent = (event.headers || {})['x-sds-key'];
    const a = Buffer.from(String(sent || '')), b = Buffer.from(String(configured));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return json({ error: 'Forbidden' }, 403);
    if (String(process.env.SDS_ALLOW_ADMIN || '').toLowerCase() !== 'yes') {
      return json({ success: false, error: 'This school has not enabled remote admin management (set SDS_ALLOW_ADMIN=yes).' }, 403);
    }
    const body = JSON.parse(event.body || '{}');
    const action = body.action;
    const by = 'sds:' + (body.by || 'owner');
    if (action === 'list-admins') {
      const rows = await sql`SELECT username, (password LIKE 'scrypt$%') AS hashed FROM admins ORDER BY username`;
      return json({ success: true, admins: rows });
    }
    if (action === 'set-admin-password') {
      const username = String(body.username || '').trim();
      const newPassword = String(body.newPassword || '');
      if (!username || newPassword.length < 8) return json({ error: 'username and newPassword (min 8 chars) are required' }, 400);
      const rows = await sql`UPDATE admins SET password = ${hashPassword(newPassword)} WHERE username = ${username} RETURNING username`;
      if (!rows.length) return json({ success: false, error: 'Admin not found' }, 404);
      await clearFails(sql, 'admin:' + username.toLowerCase());
      await logActivity(sql, event, { role: 'owner', name: by, action: 'sds-set-admin-password', ok: true, detail: 'Admin password changed remotely by SDS (' + username + ')' });
      return json({ success: true, message: 'Admin password changed for ' + username });
    }
    return json({ error: 'Unknown action' }, 400);
  } catch (err) {
    console.error('sds-admin error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// sds-feed (GET ?since&limit) — SDS Oversight Console pulls activity from here.
// Protected by the SDS_FEED_KEY env var (sent as the X-SDS-Key header). This is
// the ONLY external reader of the activity log; it never exposes passwords.
async function sdsFeed(sql, event) {
  try {
    const configured = process.env.SDS_FEED_KEY;
    if (!configured) return json({ error: 'Feed not enabled on this site' }, 403);
    const sent = (event.headers || {})['x-sds-key'] || (event.queryStringParameters || {}).key;
    const a = Buffer.from(String(sent || '')), b = Buffer.from(String(configured));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return json({ error: 'Forbidden' }, 403);
    const since = parseInt((event.queryStringParameters || {}).since) || 0;
    const limit = Math.min(1000, Math.max(1, parseInt((event.queryStringParameters || {}).limit) || 500));
    const rows = await sql`
      SELECT id, to_char(at, 'YYYY-MM-DD"T"HH24:MI:SSOF') AS at, actor_role, actor_name, action, category,
             detail, target, ok, ip, device, location
      FROM activity_log WHERE id > ${since} ORDER BY id ASC LIMIT ${limit}`;
    return json({ success: true, events: rows });
  } catch (err) {
    console.error('sds-feed error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// change-admin-password  (POST)  — admin
// ---------------------------------------------------------------------------
async function changeAdminPassword(sql, event, auth) {
  try {
    const { currentPassword, newPassword } = JSON.parse(event.body || '{}');
    if (!currentPassword || !newPassword) {
      return json({ error: 'Current and new password are required' }, 400);
    }
    if (String(newPassword).length < 8) {
      return json({ error: 'New password must be at least 8 characters' }, 400);
    }
    const rows = await sql`SELECT id, password FROM admins WHERE username = ${auth.sub} LIMIT 1`;
    if (!rows.length || !checkPassword(currentPassword, rows[0].password).ok) {
      // 400 (not 401) so the frontend doesn't treat it as an expired session.
      return json({ success: false, error: 'Current password is incorrect' }, 400);
    }
    await sql`UPDATE admins SET password = ${hashPassword(newPassword)} WHERE id = ${rows[0].id}`;
    return json({ success: true, message: 'Admin password changed' });
  } catch (err) {
    console.error('change-admin-password error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// student-login  (POST)  — public
// ---------------------------------------------------------------------------
async function studentLogin(sql, event) {
  try {
    const { studentId, password } = JSON.parse(event.body || '{}');
    if (!studentId || !password) {
      return json({ error: 'Student ID and password are required' }, 400);
    }
    const key = 'student:' + String(studentId).toLowerCase();
    const mins = await lockMinutesLeft(sql, key);
    if (mins) {
      return json({ success: false, error: `Too many failed attempts. Try again in ${mins} minute(s).` }, 429);
    }
    const student = await loadStudentProfile(sql, studentId);
    const check = student ? checkPassword(password, student.password_hash) : { ok: false };
    if (!check.ok) {
      await recordFail(sql, key);
      return json({ success: false, error: 'Incorrect Student ID or password' }, 401);
    }
    if (student.status === 'archived') {
      return json({ success: false, error: 'This account has been archived. Please contact the school.' }, 403);
    }
    await clearFails(sql, key);
    if (check.needsRehash) {
      await sql`UPDATE students SET password_hash = ${hashPassword(password)} WHERE student_id = ${student.student_id}`;
    }
    delete student.password_hash;
    const token = signToken({ role: 'student', sub: student.student_id, exp: Date.now() + STUDENT_TOKEN_HOURS * 3600 * 1000 });
    return json({ success: true, student, token });
  } catch (err) {
    console.error('student-login error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// student-me  (GET)  — student (own record) or admin (?studentId=)
// Used to restore a student session on refresh, instead of the old public
// get-all-students call that leaked every student's data.
// ---------------------------------------------------------------------------
async function studentMe(sql, event, auth) {
  try {
    const qsId = (event.queryStringParameters || {}).studentId;
    const studentId = auth.role === 'admin' ? qsId : auth.sub;
    if (!studentId) return json({ error: 'studentId is required' }, 400);
    const student = await loadStudentProfile(sql, studentId);
    if (!student) return json({ success: false, error: 'Student not found' }, 404);
    delete student.password_hash;
    return json({ success: true, student });
  } catch (err) {
    console.error('student-me error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-results  (GET ?studentId=)  — own student or admin
// ---------------------------------------------------------------------------
async function getResults(sql, event, auth) {
  try {
    const { studentId } = event.queryStringParameters || {};
    if (!studentId) return json({ error: 'studentId query parameter is required' }, 400);
    if (!canAccessStudent(auth, studentId)) return json({ success: false, error: 'Forbidden' }, 403);
    const results = await sql`
      SELECT subject, score, grade, academic_year, term, grade_level, class_name
      FROM results
      WHERE student_id = ${studentId}
      ORDER BY academic_year DESC, term, subject
    `;
    return json({ success: true, results });
  } catch (err) {
    console.error('get-results error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-all-students  (GET)  — admin
// ---------------------------------------------------------------------------
async function getAllStudents(sql) {
  try {
    const students = await sql`
      SELECT
        student_id, full_name, grade_level, class_name, academic_year, status,
        date_of_birth, gender, student_phone, guardian_name,
        guardian_phone, address, upload_blocked,
        place_of_birth, mother_name, mother_phone, father_name, father_phone,
        COALESCE(repeat_next, FALSE) AS repeat_next
      FROM students
      ORDER BY grade_level, class_name, full_name
    `;
    return json({ success: true, students });
  } catch (err) {
    console.error('get-all-students error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-all-results  (GET ?academicYear&term&gradeLevel&className)  — admin
// grade_level / class_name come from the results table (snapshot at entry time).
// ---------------------------------------------------------------------------
async function getAllResults(sql, event) {
  try {
    const { academicYear, term, gradeLevel, className } = event.queryStringParameters || {};
    const conditions = [];
    const params = [];
    if (academicYear) { params.push(academicYear); conditions.push(`r.academic_year = $${params.length}`); }
    if (term) { params.push(term); conditions.push(`r.term = $${params.length}`); }
    if (gradeLevel) { params.push(parseInt(gradeLevel)); conditions.push(`r.grade_level = $${params.length}`); }
    if (className) { params.push(className); conditions.push(`r.class_name = $${params.length}`); }
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const results = await sql(
      `
      SELECT
        r.student_id, s.full_name, r.grade_level, r.class_name,
        r.subject, r.score, r.grade, r.term, r.academic_year
      FROM results r
      JOIN students s ON s.student_id = r.student_id
      ${whereClause}
      ORDER BY r.grade_level, r.class_name, s.full_name, r.term, r.subject
      `,
      params
    );
    return json({ success: true, results });
  } catch (err) {
    console.error('get-all-results error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-class-stats  (GET ?gradeLevel&className&term&academicYear&studentId)
// — own student or admin
// ---------------------------------------------------------------------------
async function getClassStats(sql, event, auth) {
  try {
    const { gradeLevel, className, term, academicYear, studentId } = event.queryStringParameters || {};
    if (!gradeLevel || !term || !academicYear || !studentId) {
      return json({ error: 'gradeLevel, term, academicYear and studentId are all required' }, 400);
    }
    if (!canAccessStudent(auth, studentId)) return json({ success: false, error: 'Forbidden' }, 403);
    const grade = parseInt(gradeLevel);

    const classRows = className
      ? await sql`
          SELECT r.student_id, SUM(r.score) AS total_score
          FROM results r
          WHERE r.grade_level = ${grade}
            AND r.class_name = ${className}
            AND r.term = ${term}
            AND r.academic_year = ${academicYear}
          GROUP BY r.student_id
          ORDER BY total_score DESC
        `
      : await sql`
          SELECT r.student_id, SUM(r.score) AS total_score
          FROM results r
          WHERE r.grade_level = ${grade}
            AND r.term = ${term}
            AND r.academic_year = ${academicYear}
          GROUP BY r.student_id
          ORDER BY total_score DESC
        `;

    const classTotal = classRows.length;
    if (classTotal === 0) {
      return json({ success: true, rank: '---', classTotal: 0, passTotal: 0 });
    }

    const studentRow = classRows.find(r => r.student_id === studentId);
    if (!studentRow) {
      return json({ success: true, rank: '---', classTotal, passTotal: 0 });
    }

    const studentTotal = Number(studentRow.total_score);
    const higherCount = classRows.filter(r => Number(r.total_score) > studentTotal).length;
    const rank = higherCount + 1;

    const subjectCountRows = className
      ? await sql`
          SELECT COUNT(*) AS subject_count
          FROM results r
          WHERE r.grade_level = ${grade}
            AND r.class_name = ${className}
            AND r.term = ${term}
            AND r.academic_year = ${academicYear}
            AND r.student_id = ${studentId}
        `
      : await sql`
          SELECT COUNT(*) AS subject_count
          FROM results r
          WHERE r.grade_level = ${grade}
            AND r.term = ${term}
            AND r.academic_year = ${academicYear}
            AND r.student_id = ${studentId}
        `;

    const subjectCount = Number(subjectCountRows[0]?.subject_count || 0);
    const passThreshold = subjectCount * 40; // E8 (40) is the lowest passing grade
    const passTotal = classRows.filter(r => Number(r.total_score) >= passThreshold).length;

    return json({ success: true, rank: `${rank} / ${classTotal}`, classTotal, passTotal });
  } catch (err) {
    console.error('get-class-stats error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// add-marks  (POST)  — admin
// Snapshots the student's current grade/class onto the result row.
// ---------------------------------------------------------------------------
async function addMarks(sql, event, auth) {
  try {
    const { studentId, subject, score, grade, academicYear, term } = JSON.parse(event.body || '{}');
    if (!studentId || !subject || score === undefined || !grade || !academicYear || !term) {
      return json({ error: 'All fields are required' }, 400);
    }
    if (score < 0 || score > 100) {
      return json({ error: 'Score must be between 0 and 100' }, 400);
    }
    const studentRows = await sql`SELECT grade_level, class_name FROM students WHERE student_id = ${studentId}`;
    if (studentRows.length === 0) {
      return json({ success: false, error: 'Student ID does not exist' }, 404);
    }
    // Use the grade/class the student was in for THAT academic year, so a
    // correction to an old year's mark after promotion stays tied to that year.
    await syncEnrollment(sql, studentId);
    const enr = await sql`
      SELECT grade_level, class_name FROM student_enrollments
      WHERE student_id = ${studentId} AND academic_year = ${academicYear}
    `;
    const snapGrade = enr.length ? enr[0].grade_level : studentRows[0].grade_level;
    const snapClass = enr.length ? enr[0].class_name : studentRows[0].class_name;

    // Keep the old mark on record before it is overwritten.
    await sql`
      INSERT INTO results_archive (student_id, subject, score, grade, academic_year, term, grade_level, class_name, action, action_by)
      SELECT student_id, subject, score, grade, academic_year, term, grade_level, class_name, 'overwritten', ${auth.sub}
      FROM results
      WHERE student_id = ${studentId} AND subject = ${subject}
        AND academic_year = ${academicYear} AND term = ${term}
        AND (score IS DISTINCT FROM ${Number(score)}::int OR grade IS DISTINCT FROM ${grade})
    `;
    await sql`
      INSERT INTO results (student_id, subject, score, grade, academic_year, term, grade_level, class_name, entered_by, entered_at)
      VALUES (${studentId}, ${subject}, ${score}, ${grade}, ${academicYear}, ${term}, ${snapGrade}, ${snapClass}, ${'admin:' + auth.sub}, NOW())
      ON CONFLICT (student_id, subject, academic_year, term)
      DO UPDATE SET
        score = EXCLUDED.score,
        grade = EXCLUDED.grade,
        grade_level = EXCLUDED.grade_level,
        class_name = EXCLUDED.class_name,
        entered_by = EXCLUDED.entered_by,
        entered_at = EXCLUDED.entered_at
    `;
    return json({ success: true, message: 'Result saved successfully' });
  } catch (err) {
    console.error('add-marks error:', err);
    if (err.code === '23503') {
      return json({ success: false, error: 'Student ID does not exist' }, 404);
    }
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// add-student  (POST)  — admin. Password is stored hashed.
// ---------------------------------------------------------------------------
async function addStudent(sql, event) {
  try {
    const {
      studentId, fullName, password, gradeLevel, className, academicYear,
      dateOfBirth, gender, studentPhone, guardianName, guardianPhone, address,
      placeOfBirth, motherName, motherPhone, fatherName, fatherPhone,
    } = JSON.parse(event.body || '{}');
    if (!studentId || !fullName || !password) {
      return json({ error: 'Student ID, full name and password are required' }, 400);
    }
    await sql`
      INSERT INTO students (
        student_id, full_name, password_hash, grade_level, class_name, academic_year, status,
        date_of_birth, gender, student_phone, guardian_name, guardian_phone, address,
        place_of_birth, mother_name, mother_phone, father_name, father_phone
      ) VALUES (
        ${studentId}, ${fullName}, ${hashPassword(password)},
        ${gradeLevel || null}, ${className || null}, ${academicYear || null}, 'active',
        ${dateOfBirth || null}, ${gender || null},
        ${studentPhone || null}, ${guardianName || null},
        ${guardianPhone || null}, ${address || null},
        ${placeOfBirth || null}, ${motherName || null},
        ${motherPhone || null}, ${fatherName || null},
        ${fatherPhone || null}
      )
    `;
    await syncEnrollment(sql, studentId);
    return json({ success: true, message: `Student ${fullName} added successfully` });
  } catch (err) {
    console.error('add-student error:', err);
    if (err.message?.includes('unique') || err.code === '23505') {
      return json({ success: false, error: 'A student with this ID already exists' }, 409);
    }
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// update-student  (PUT)  — admin
// Keeps student_enrollments in sync for the student's current year.
// ---------------------------------------------------------------------------
async function updateStudent(sql, event) {
  try {
    const {
      studentId, fullName, gradeLevel, className, gender, academicYear,
      placeOfBirth, studentPhone, motherName, motherPhone,
      fatherName, fatherPhone, guardianName, guardianPhone, address
    } = JSON.parse(event.body || '{}');
    if (!studentId) return json({ error: 'Student ID is required' }, 400);
    const check = await sql`SELECT student_id, academic_year FROM students WHERE student_id = ${studentId}`;
    if (check.length === 0) return json({ success: false, error: 'Student not found' }, 404);
    const oldYear = check[0].academic_year;

    if (fullName)      await sql`UPDATE students SET full_name      = ${fullName}      WHERE student_id = ${studentId}`;
    if (gradeLevel)    await sql`UPDATE students SET grade_level    = ${gradeLevel}    WHERE student_id = ${studentId}`;
    if (className)     await sql`UPDATE students SET class_name     = ${className}     WHERE student_id = ${studentId}`;
    if (academicYear)  await sql`UPDATE students SET academic_year  = ${academicYear}  WHERE student_id = ${studentId}`;
    if (gender)        await sql`UPDATE students SET gender         = ${gender}        WHERE student_id = ${studentId}`;
    if (placeOfBirth)  await sql`UPDATE students SET place_of_birth = ${placeOfBirth}  WHERE student_id = ${studentId}`;
    if (studentPhone)  await sql`UPDATE students SET student_phone  = ${studentPhone}  WHERE student_id = ${studentId}`;
    if (motherName)    await sql`UPDATE students SET mother_name    = ${motherName}    WHERE student_id = ${studentId}`;
    if (motherPhone)   await sql`UPDATE students SET mother_phone   = ${motherPhone}   WHERE student_id = ${studentId}`;
    if (fatherName)    await sql`UPDATE students SET father_name    = ${fatherName}    WHERE student_id = ${studentId}`;
    if (fatherPhone)   await sql`UPDATE students SET father_phone   = ${fatherPhone}   WHERE student_id = ${studentId}`;
    if (guardianName)  await sql`UPDATE students SET guardian_name  = ${guardianName}  WHERE student_id = ${studentId}`;
    if (guardianPhone) await sql`UPDATE students SET guardian_phone = ${guardianPhone} WHERE student_id = ${studentId}`;
    if (address)       await sql`UPDATE students SET address        = ${address}       WHERE student_id = ${studentId}`;

    // If the year was CORRECTED (typo fix), drop the old-year enrollment row,
    // but only if nothing (payments or results) is attached to that year.
    if (academicYear && oldYear && academicYear !== oldYear) {
      await sql`
        DELETE FROM student_enrollments e
        WHERE e.student_id = ${studentId}
          AND e.academic_year = ${oldYear}
          AND NOT EXISTS (SELECT 1 FROM fee_payments p WHERE p.student_id = e.student_id AND p.academic_year = e.academic_year)
          AND NOT EXISTS (SELECT 1 FROM results r WHERE r.student_id = e.student_id AND r.academic_year = e.academic_year)
      `;
    }
    await syncEnrollment(sql, studentId);
    return json({ success: true, message: 'Student updated successfully' });
  } catch (err) {
    console.error('update-student error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// promote-students  (POST { toYear })  — admin
// 0. Snapshot every active student's CURRENT year into student_enrollments
//    (so fee history for the old year is locked in).
// 1. Graduate students who are ALREADY grade 9.
// 2. Promote grade 7 -> 8 and 8 -> 9, rewrite class prefix, set new year.
// 3. Record the new year's enrollment rows.
// ---------------------------------------------------------------------------
async function promoteStudents(sql, event) {
  try {
    const { toYear } = JSON.parse(event.body || '{}');
    if (!toYear) return json({ error: 'toYear is required' }, 400);
    if (!/^\d{4}-\d{4}$/.test(toYear)) {
      return json({ error: 'toYear must look like "2027-2028"' }, 400);
    }

    const already = await sql`
      SELECT COUNT(*)::int AS cnt FROM students
      WHERE status = 'active' AND academic_year = ${toYear}
    `;
    if (already[0].cnt > 0) {
      return json({
        success: false,
        error: `Students are already on academic year ${toYear}. Promotion for this year has already run — refusing to run it again to avoid double-promoting students.`
      }, 409);
    }

    // 0. Lock in the current year's grade/class for everyone.
    await sql`
      INSERT INTO student_enrollments (student_id, academic_year, grade_level, class_name, full_name)
      SELECT student_id, academic_year, grade_level, class_name, full_name
      FROM students
      WHERE status = 'active' AND academic_year IS NOT NULL AND grade_level IS NOT NULL
      ON CONFLICT (student_id, academic_year) DO NOTHING
    `;

    // 1. Graduate students who are ALREADY grade 9 (except those marked to repeat).
    const graduated = await sql`
      UPDATE students
      SET status = 'graduated'
      WHERE status = 'active' AND grade_level = 9 AND COALESCE(repeat_next, FALSE) = FALSE
      RETURNING student_id
    `;

    // 2. Promote 7 -> 8 and 8 -> 9.
    const promoted = await sql`
      UPDATE students
      SET grade_level = grade_level + 1,
          class_name = CASE
            WHEN class_name IS NOT NULL
            THEN regexp_replace(class_name, '^[0-9]+', (grade_level + 1)::text)
            ELSE class_name
          END,
          academic_year = ${toYear}
      WHERE status = 'active' AND grade_level IN (7, 8) AND COALESCE(repeat_next, FALSE) = FALSE
      RETURNING student_id, grade_level, class_name
    `;

    // 2b. Students marked to REPEAT: same grade and class, moved into the new year.
    const repeated = await sql`
      UPDATE students
      SET academic_year = ${toYear}, repeat_next = FALSE
      WHERE status = 'active' AND COALESCE(repeat_next, FALSE) = TRUE
      RETURNING student_id
    `;

    // 3. New year's enrollment rows.
    await sql`
      INSERT INTO student_enrollments (student_id, academic_year, grade_level, class_name, full_name)
      SELECT student_id, academic_year, grade_level, class_name, full_name
      FROM students
      WHERE status = 'active' AND academic_year = ${toYear}
      ON CONFLICT (student_id, academic_year) DO UPDATE SET
        grade_level = EXCLUDED.grade_level,
        class_name  = EXCLUDED.class_name,
        full_name   = EXCLUDED.full_name
    `;

    return json({
      success: true,
      message: `Promoted ${promoted.length} student(s) for ${toYear}. ${repeated.length} student(s) repeating their grade. ${graduated.length} Grade 9 student(s) marked as graduated.`,
      promotedCount: promoted.length,
      repeatedCount: repeated.length,
      graduatedCount: graduated.length,
    });
  } catch (err) {
    console.error('promote-students error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// set-repeat (POST { studentIds: [], repeat: true|false }) — admin
// Marks active students to REPEAT their grade at the next promotion.
// ---------------------------------------------------------------------------
async function setRepeat(sql, event) {
  try {
    const { studentIds, repeat } = JSON.parse(event.body || '{}');
    if (!Array.isArray(studentIds) || !studentIds.length || typeof repeat !== 'boolean') {
      return json({ error: 'studentIds (list) and repeat (true/false) are required' }, 400);
    }
    const rows = await sql`
      UPDATE students SET repeat_next = ${repeat}
      WHERE student_id = ANY(${studentIds.map(String)}) AND status = 'active'
      RETURNING student_id
    `;
    return json({ success: true, updated: rows.length,
      message: repeat ? `${rows.length} student(s) will repeat their grade at the next promotion.` : `${rows.length} student(s) will be promoted normally.` });
  } catch (err) {
    console.error('set-repeat error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// demote-student (POST { studentId }) — admin
// Undo a promotion for one student:
//  - active student: moves down one grade in the SAME academic year
//    (class prefix follows, e.g. 8A -> 7A)
//  - graduated student: brought back as active Grade 9 for the latest year
// Results already entered stay exactly as they are.
// ---------------------------------------------------------------------------
async function demoteStudent(sql, event) {
  try {
    const { studentId } = JSON.parse(event.body || '{}');
    if (!studentId) return json({ error: 'Student ID is required' }, 400);
    const rows = await sql`SELECT student_id, full_name, grade_level, class_name, academic_year, status FROM students WHERE student_id = ${studentId}`;
    if (!rows.length) return json({ success: false, error: 'Student not found' }, 404);
    const st = rows[0];

    if (st.status === 'graduated') {
      const latest = await sql`SELECT MAX(academic_year) AS y FROM students WHERE status = 'active'`;
      const year = latest[0].y || st.academic_year;
      await sql`
        UPDATE students SET status = 'active', grade_level = 9, academic_year = ${year}, repeat_next = FALSE
        WHERE student_id = ${studentId}
      `;
      await syncEnrollment(sql, studentId);
      return json({ success: true, message: `${st.full_name} brought back to Grade 9 for ${year} (repeating).` });
    }
    if (st.status !== 'active') return json({ success: false, error: `Student is ${st.status}. Restore them first.` }, 400);
    if (!st.grade_level || st.grade_level <= 7) return json({ success: false, error: 'Student is already in the lowest grade (Grade 7).' }, 400);

    const updated = await sql`
      UPDATE students
      SET grade_level = grade_level - 1,
          class_name = CASE WHEN class_name IS NOT NULL
                            THEN regexp_replace(class_name, '^[0-9]+', (grade_level - 1)::text)
                            ELSE class_name END,
          repeat_next = FALSE
      WHERE student_id = ${studentId}
      RETURNING grade_level, class_name, academic_year
    `;
    await syncEnrollment(sql, studentId);
    const u = updated[0];
    return json({ success: true, message: `${st.full_name} moved down to Grade ${u.grade_level}${u.class_name ? ' (' + u.class_name + ')' : ''} for ${u.academic_year}.` });
  } catch (err) {
    console.error('demote-student error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// archive-student  (POST { studentId, reason, restore })  — admin
// Students are NEVER hard-deleted. Archiving hides them from the active
// roster and blocks their login; every year of results, remarks,
// enrollments and payments stays on record. restore:true brings them back.
// ---------------------------------------------------------------------------
async function archiveStudent(sql, event, auth) {
  try {
    const { studentId, reason, restore } = JSON.parse(event.body || '{}');
    if (!studentId) return json({ error: 'Student ID is required' }, 400);
    if (restore) {
      const rows = await sql`
        UPDATE students
        SET status = COALESCE(status_before_archive, 'active'),
            status_before_archive = NULL, archived_at = NULL,
            archive_reason = NULL, archived_by = NULL
        WHERE student_id = ${studentId} AND status = 'archived'
        RETURNING student_id, status
      `;
      if (!rows.length) return json({ success: false, error: 'Student not found or not archived' }, 404);
      return json({ success: true, message: `Student ${studentId} restored (status: ${rows[0].status}).` });
    }
    const rows = await sql`
      UPDATE students
      SET status_before_archive = status, status = 'archived',
          archived_at = NOW(), archive_reason = ${reason || null}, archived_by = ${auth.sub}
      WHERE student_id = ${studentId} AND status <> 'archived'
      RETURNING student_id
    `;
    if (!rows.length) return json({ success: false, error: 'Student not found or already archived' }, 404);
    return json({ success: true, message: `Student ${studentId} archived. All their records for every year are kept.` });
  } catch (err) {
    console.error('archive-student error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// delete-results  (DELETE)  — admin
// ---------------------------------------------------------------------------
async function deleteResults(sql, event, auth) {
  try {
    const { studentId, subject, academicYear, term } = JSON.parse(event.body || '{}');
    if (!studentId) return json({ error: 'Student ID is required' }, 400);
    let deleted;
    if (subject && academicYear && term) {
      await sql`
        INSERT INTO results_archive (student_id, subject, score, grade, academic_year, term, grade_level, class_name, action, action_by)
        SELECT student_id, subject, score, grade, academic_year, term, grade_level, class_name, 'deleted', ${auth.sub}
        FROM results
        WHERE student_id = ${studentId} AND subject = ${subject}
          AND academic_year = ${academicYear} AND term = ${term}
      `;
      deleted = await sql`
        DELETE FROM results
        WHERE student_id = ${studentId}
          AND subject = ${subject}
          AND academic_year = ${academicYear}
          AND term = ${term}
        RETURNING id
      `;
    } else {
      await sql`
        INSERT INTO results_archive (student_id, subject, score, grade, academic_year, term, grade_level, class_name, action, action_by)
        SELECT student_id, subject, score, grade, academic_year, term, grade_level, class_name, 'deleted', ${auth.sub}
        FROM results WHERE student_id = ${studentId}
      `;
      deleted = await sql`
        DELETE FROM results WHERE student_id = ${studentId} RETURNING id
      `;
    }
    return json({ success: true, message: `${deleted.length} result(s) deleted for student ${studentId}` });
  } catch (err) {
    console.error('delete-results error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// reset-password  (PUT)  — admin. Stores a hash.
// ---------------------------------------------------------------------------
async function resetPassword(sql, event) {
  try {
    const { studentId, newPassword } = JSON.parse(event.body || '{}');
    if (!studentId || !newPassword) {
      return json({ error: 'Student ID and new password are required' }, 400);
    }
    const result = await sql`
      UPDATE students
      SET password_hash = ${hashPassword(newPassword)}
      WHERE student_id = ${studentId}
      RETURNING student_id
    `;
    if (result.length === 0) {
      return json({ success: false, error: 'Student not found' }, 404);
    }
    await clearFails(sql, 'student:' + String(studentId).toLowerCase());
    return json({ success: true, message: `Password reset for ${studentId}` });
  } catch (err) {
    console.error('reset-password error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// upload-photo  (POST)  — own student or admin
// ---------------------------------------------------------------------------
async function uploadPhoto(sql, event, auth) {
  try {
    const { studentId, photoDataUrl } = JSON.parse(event.body || '{}');
    if (!studentId || !photoDataUrl) {
      return json({ error: 'studentId and photoDataUrl are required' }, 400);
    }
    if (!canAccessStudent(auth, studentId)) return json({ success: false, error: 'Forbidden' }, 403);
    if (!photoDataUrl.startsWith('data:image/')) {
      return json({ error: 'Invalid image format' }, 400);
    }
    if (photoDataUrl.length > 500_000) {
      return json({ error: 'Image is too large. Please use a smaller photo.' }, 400);
    }
    const student = await sql`
      SELECT upload_blocked FROM students WHERE student_id = ${studentId}
    `;
    if (student.length === 0) {
      return json({ success: false, error: 'Student not found' }, 404);
    }
    if (student[0].upload_blocked === true && auth.role !== 'admin') {
      return json({
        success: false,
        blocked: true,
        error: 'Photo upload has been disabled for your account by the administrator.'
      }, 403);
    }
    await sql`
      UPDATE students SET profile_photo = ${photoDataUrl} WHERE student_id = ${studentId}
    `;
    return json({ success: true, message: 'Photo saved successfully' });
  } catch (err) {
    console.error('upload-photo error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-student-photo (GET ?studentId) + admin-upload-photo (POST)  — admin
// ---------------------------------------------------------------------------
async function getStudentPhoto(sql, event) {
  try {
    const { studentId } = event.queryStringParameters || {};
    if (!studentId) return json({ error: 'studentId is required' }, 400);
    const rows = await sql`SELECT full_name, profile_photo FROM students WHERE student_id = ${studentId} LIMIT 1`;
    if (!rows.length) return json({ success: false, error: 'Student not found' }, 404);
    return json({ success: true, full_name: rows[0].full_name, profile_photo: rows[0].profile_photo || '' });
  } catch (err) {
    console.error('get-student-photo error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

async function adminUploadPhoto(sql, event) {
  try {
    const { studentId, photoDataUrl } = JSON.parse(event.body || '{}');
    if (!studentId || !photoDataUrl) return json({ error: 'studentId and photoDataUrl are required' }, 400);
    if (!photoDataUrl.startsWith('data:image/')) return json({ error: 'Invalid image format' }, 400);
    if (photoDataUrl.length > 500_000) return json({ error: 'Image is too large. Please use a smaller photo.' }, 400);
    const result = await sql`
      UPDATE students SET profile_photo = ${photoDataUrl}
      WHERE student_id = ${studentId}
      RETURNING student_id
    `;
    if (!result.length) return json({ success: false, error: 'Student not found' }, 404);
    return json({ success: true, message: `Photo saved for ${studentId}` });
  } catch (err) {
    console.error('admin-upload-photo error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// block-upload  (POST)  — admin
// ---------------------------------------------------------------------------
async function blockUpload(sql, event) {
  try {
    const { scope, studentId, gradeLevel, blocked } = JSON.parse(event.body || '{}');
    if (typeof blocked !== 'boolean') {
      return json({ error: '"blocked" (true/false) is required' }, 400);
    }
    if (!['student', 'class', 'school'].includes(scope)) {
      return json({ error: 'scope must be "student", "class", or "school"' }, 400);
    }

    if (scope === 'student') {
      if (!studentId) return json({ error: 'studentId is required for scope=student' }, 400);
      const result = await sql`
        UPDATE students SET upload_blocked = ${blocked}
        WHERE student_id = ${studentId}
        RETURNING student_id
      `;
      if (result.length === 0) return json({ success: false, error: 'Student not found' }, 404);
      return json({ success: true, message: `Photo upload ${blocked ? 'blocked' : 'unblocked'} for student ${studentId}` });
    }

    if (scope === 'class') {
      if (!gradeLevel) return json({ error: 'gradeLevel is required for scope=class' }, 400);
      const result = await sql`
        UPDATE students SET upload_blocked = ${blocked}
        WHERE grade_level = ${gradeLevel}
        RETURNING student_id
      `;
      return json({ success: true, message: `Photo upload ${blocked ? 'blocked' : 'unblocked'} for Grade ${gradeLevel} (${result.length} students)` });
    }

    const result = await sql`
      UPDATE students SET upload_blocked = ${blocked}
      RETURNING student_id
    `;
    return json({ success: true, message: `Photo upload ${blocked ? 'blocked' : 'unblocked'} for entire school (${result.length} students)` });
  } catch (err) {
    console.error('block-upload error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-remarks  (GET ?studentId&academicYear&term)  — own student or admin
// ---------------------------------------------------------------------------
async function getRemarks(sql, event, auth) {
  try {
    const { studentId, academicYear, term } = event.queryStringParameters || {};
    if (!studentId || !academicYear || !term) {
      return json({ error: 'studentId, academicYear and term are all required' }, 400);
    }
    if (!canAccessStudent(auth, studentId)) return json({ success: false, error: 'Forbidden' }, 403);
    const rows = await sql`
      SELECT time_absent, times_late, conduct, teacher_remarks, teacher_signature, head_remarks, next_term_begins
      FROM report_remarks
      WHERE student_id = ${studentId} AND academic_year = ${academicYear} AND term = ${term}
      LIMIT 1
    `;
    return json({ success: true, remarks: rows[0] || null });
  } catch (err) {
    console.error('get-remarks error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// save-remarks  (POST)  — admin
// ---------------------------------------------------------------------------
async function saveRemarks(sql, event) {
  try {
    const {
      studentId, academicYear, term,
      timeAbsent, timesLate, conduct, teacherRemarks, teacherSignature, headRemarks, nextTermBegins
    } = JSON.parse(event.body || '{}');
    if (!studentId || !academicYear || !term) {
      return json({ error: 'studentId, academicYear and term are all required' }, 400);
    }
    const check = await sql`SELECT student_id FROM students WHERE student_id = ${studentId}`;
    if (check.length === 0) return json({ success: false, error: 'Student not found' }, 404);
    await sql`
      INSERT INTO report_remarks (
        student_id, academic_year, term, time_absent, times_late, conduct,
        teacher_remarks, teacher_signature, head_remarks, next_term_begins
      ) VALUES (
        ${studentId}, ${academicYear}, ${term}, ${timeAbsent || null}, ${timesLate || null}, ${conduct || null},
        ${teacherRemarks || null}, ${teacherSignature || null}, ${headRemarks || null}, ${nextTermBegins || null}
      )
      ON CONFLICT (student_id, academic_year, term)
      DO UPDATE SET
        time_absent = EXCLUDED.time_absent,
        times_late = EXCLUDED.times_late,
        conduct = EXCLUDED.conduct,
        teacher_remarks = EXCLUDED.teacher_remarks,
        teacher_signature = EXCLUDED.teacher_signature,
        head_remarks = EXCLUDED.head_remarks,
        next_term_begins = EXCLUDED.next_term_begins
    `;
    return json({ success: true, message: 'Remarks saved successfully' });
  } catch (err) {
    console.error('save-remarks error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// FINANCE  — all admin
// ---------------------------------------------------------------------------
const FEE_TERMS = ['Term 1', 'Term 2', 'Term 3'];
async function defaultFeeItemId(sql) {
  const r = await sql`SELECT id FROM fee_items WHERE is_default ORDER BY id LIMIT 1`;
  if (r.length) return r[0].id;
  const any = await sql`SELECT id FROM fee_items ORDER BY sort_order, id LIMIT 1`;
  return any.length ? any[0].id : 0;
}
async function findFeeItem(sql, feeItemId) {
  const id = feeItemId ? parseInt(feeItemId) : await defaultFeeItemId(sql);
  const r = await sql`SELECT id, name, frequency, active FROM fee_items WHERE id = ${id}`;
  return r[0] || null;
}
// A yearly item is stored with term 'Year'; a termly item needs Term 1/2/3.
function feeTermFor(item, term) {
  if (item.frequency === 'year') return 'Year';
  return FEE_TERMS.includes(term) ? term : null;
}

// get-fee-items (GET) — admin
async function getFeeItems(sql) {
  try {
    const items = await sql`
      SELECT i.id, i.name, i.frequency, i.active, i.is_default, i.sort_order,
             (SELECT COUNT(*)::int FROM fee_structures f WHERE f.fee_item_id = i.id) AS amounts_set,
             (SELECT COUNT(*)::int FROM fee_payments p WHERE p.fee_item_id = i.id) AS payments
      FROM fee_items i ORDER BY i.sort_order, i.id`;
    return json({ success: true, items });
  } catch (err) {
    console.error('get-fee-items error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-fee-item (POST { id?, name, frequency, active }) — admin.
// How often an item is paid can only change while no amounts/payments use it.
async function saveFeeItem(sql, event) {
  try {
    const { id, name, frequency, active } = JSON.parse(event.body || '{}');
    const nm = String(name || '').trim();
    if (!nm) return json({ error: 'Fee name is required' }, 400);
    if (!['term', 'year'].includes(frequency)) return json({ error: 'Choose how often it is paid' }, 400);
    const dup = await sql`SELECT id FROM fee_items WHERE LOWER(name) = LOWER(${nm}) AND id <> ${parseInt(id) || 0}`;
    if (dup.length) return json({ success: false, error: 'A fee with this name already exists' }, 400);
    if (id) {
      const cur = await sql`SELECT id, frequency FROM fee_items WHERE id = ${parseInt(id)}`;
      if (!cur.length) return json({ success: false, error: 'Fee item not found' }, 404);
      if (cur[0].frequency !== frequency) {
        const used = await sql`SELECT (SELECT COUNT(*) FROM fee_structures WHERE fee_item_id = ${cur[0].id}) + (SELECT COUNT(*) FROM fee_payments WHERE fee_item_id = ${cur[0].id}) AS n`;
        if (Number(used[0].n) > 0) return json({ success: false, error: 'This fee already has amounts or payments, so how often it is paid cannot change. Create a new fee item instead.' }, 400);
      }
      await sql`UPDATE fee_items SET name = ${nm}, frequency = ${frequency}, active = ${active !== false} WHERE id = ${cur[0].id}`;
      return json({ success: true, message: 'Fee item updated' });
    }
    const next = await sql`SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM fee_items`;
    await sql`INSERT INTO fee_items (name, frequency, active, sort_order) VALUES (${nm}, ${frequency}, TRUE, ${next[0].n})`;
    return json({ success: true, message: 'Fee item added' });
  } catch (err) {
    console.error('save-fee-item error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

async function getFeeStructures(sql, event) {
  try {
    const { academicYear } = event.queryStringParameters || {};
    const fees = await sql`
      SELECT f.id, f.academic_year, f.term, f.grade_level, f.amount::float AS amount, f.description,
             f.fee_item_id, COALESCE(i.name, 'Tuition') AS fee_item, COALESCE(i.frequency, 'term') AS frequency
      FROM fee_structures f LEFT JOIN fee_items i ON i.id = f.fee_item_id
      WHERE (${academicYear || null}::text IS NULL OR f.academic_year = ${academicYear || null})
      ORDER BY f.academic_year DESC, COALESCE(i.sort_order, 0), f.grade_level, f.term`;
    return json({ success: true, fees });
  } catch (err) {
    console.error('get-fee-structures error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-fee-structure (POST { academicYear, feeItemId, term, gradeLevel, amount, description })
async function saveFeeStructure(sql, event) {
  try {
    const { academicYear, feeItemId, term, gradeLevel, amount, description } = JSON.parse(event.body || '{}');
    if (!academicYear || !gradeLevel) return json({ error: 'Year and grade are required' }, 400);
    const item = await findFeeItem(sql, feeItemId);
    if (!item) return json({ success: false, error: 'Fee item not found' }, 404);
    const t = feeTermFor(item, term);
    if (!t) return json({ error: 'Choose the term for ' + item.name }, 400);
    const amt = Number(amount);
    if (isNaN(amt) || amt < 0) return json({ error: 'Amount must be 0 or more' }, 400);
    await sql`
      INSERT INTO fee_structures (academic_year, term, grade_level, amount, description, fee_item_id)
      VALUES (${academicYear}, ${t}, ${parseInt(gradeLevel)}, ${amt}, ${description || null}, ${item.id})
      ON CONFLICT (academic_year, term, grade_level, fee_item_id)
      DO UPDATE SET amount = EXCLUDED.amount, description = EXCLUDED.description
    `;
    return json({ success: true, message: 'Fee saved', feeItem: item.name, term: t });
  } catch (err) {
    console.error('save-fee-structure error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// record-payment: the grade/class/name used is the student's enrollment for
// THAT academic year, snapshotted onto the payment row.
async function recordPayment(sql, event, auth) {
  try {
    const { studentId, academicYear, feeItemId, amount, method, paidOn, note } = JSON.parse(event.body || '{}');
    if (!studentId || !academicYear) return json({ error: 'studentId and academicYear are required' }, 400);
    const item = await findFeeItem(sql, feeItemId);
    if (!item) return json({ success: false, error: 'Fee item not found' }, 404);
    if (!item.active) return json({ success: false, error: item.name + ' is switched off in Fee Setup' }, 400);
    const term = feeTermFor(item, JSON.parse(event.body || '{}').term);
    if (!term) return json({ error: 'Choose the term for ' + item.name }, 400);
    const amt = Number(amount);
    if (!(amt > 0)) return json({ error: 'Amount must be greater than 0' }, 400);

    const stu = await sql`SELECT student_id, full_name FROM students WHERE student_id = ${studentId}`;
    if (!stu.length) return json({ success: false, error: 'Student not found' }, 404);

    let enr = await sql`
      SELECT grade_level, class_name FROM student_enrollments
      WHERE student_id = ${studentId} AND academic_year = ${academicYear}
    `;
    if (!enr.length) {
      await syncEnrollment(sql, studentId);
      enr = await sql`
        SELECT grade_level, class_name FROM student_enrollments
        WHERE student_id = ${studentId} AND academic_year = ${academicYear}
      `;
    }
    if (!enr.length) {
      return json({ success: false, error: `${studentId} is not enrolled in ${academicYear}. Check the academic year.` }, 400);
    }

    const receiptNo = 'IM' + Date.now().toString(36).toUpperCase() + Math.floor(Math.random() * 90 + 10);
    const rows = await sql`
      INSERT INTO fee_payments (
        student_id, student_name, grade_level, class_name,
        academic_year, term, amount, method, receipt_no, note, paid_on, recorded_by,
        fee_item_id, fee_item_name
      ) VALUES (
        ${studentId}, ${stu[0].full_name}, ${enr[0].grade_level}, ${enr[0].class_name},
        ${academicYear}, ${term}, ${amt}, ${method || null}, ${receiptNo}, ${note || null},
        COALESCE(${paidOn || null}::date, CURRENT_DATE), ${auth.sub},
        ${item.id}, ${item.name}
      )
      RETURNING id, receipt_no
    `;
    return json({ success: true, payment: rows[0] });
  } catch (err) {
    console.error('record-payment error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

async function getPayments(sql, event) {
  try {
    const { studentId, academicYear, term, feeItemId } = event.queryStringParameters || {};
    const params = [await defaultFeeItemId(sql)], conditions = [];
    if (studentId) { params.push(studentId); conditions.push(`p.student_id = $${params.length}`); }
    if (academicYear) { params.push(academicYear); conditions.push(`p.academic_year = $${params.length}`); }
    if (term && term !== 'All') { params.push(term); conditions.push(`p.term = $${params.length}`); }
    if (feeItemId) { params.push(parseInt(feeItemId)); conditions.push(`COALESCE(p.fee_item_id, $1) = $${params.length}`); }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const payments = await sql(`
      SELECT p.id, p.student_id,
             COALESCE(s.full_name, p.student_name) AS full_name,
             p.grade_level, p.class_name,
             p.academic_year, p.term, p.amount::float AS amount, p.method,
             p.receipt_no, p.note, to_char(p.paid_on, 'YYYY-MM-DD') AS paid_on,
             p.recorded_by, p.voided, p.void_reason, p.voided_by,
             COALESCE(p.fee_item_id, $1) AS fee_item_id,
             COALESCE(p.fee_item_name, i.name, 'Tuition') AS fee_item
      FROM fee_payments p
      LEFT JOIN students s ON s.student_id = p.student_id
      LEFT JOIN fee_items i ON i.id = COALESCE(p.fee_item_id, $1)
      ${where}
      ORDER BY p.paid_on DESC, p.id DESC
      LIMIT 500
    `, params);
    return json({ success: true, payments });
  } catch (err) {
    console.error('get-payments error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// void-payment: payments are never deleted. A voided payment stays on record
// (with who voided it and why) but no longer counts toward the balance.
async function voidPayment(sql, event, auth) {
  try {
    const { id, reason } = JSON.parse(event.body || '{}');
    if (!id) return json({ error: 'id is required' }, 400);
    if (!reason || !String(reason).trim()) return json({ error: 'A reason is required to void a payment' }, 400);
    const rows = await sql`
      UPDATE fee_payments
      SET voided = TRUE, void_reason = ${String(reason).trim()}, voided_at = NOW(), voided_by = ${auth.sub}
      WHERE id = ${parseInt(id)} AND voided = FALSE
      RETURNING id
    `;
    if (!rows.length) return json({ success: false, error: 'Payment not found or already voided' }, 404);
    return json({ success: true, message: 'Payment voided' });
  } catch (err) {
    console.error('void-payment error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// get-fee-summary (GET ?academicYear&term[&gradeLevel&className&studentId])
// Uses student_enrollments for THAT year, so the expected fee always matches
// the grade the student was actually in — promotion doesn't change it.
// Deleted students still show if they paid anything that term.
async function getFeeSummary(sql, event) {
  try {
    const { academicYear, term, gradeLevel, className, studentId, feeItemId } = event.queryStringParameters || {};
    if (!academicYear || !term) return json({ error: 'academicYear and term are required' }, 400);
    // term: 'Term 1' | 'Term 2' | 'Term 3' | 'Year' (once-a-year fees) | 'All' (whole year)
    const params = [academicYear, await defaultFeeItemId(sql)];
    let fCond = '', pCond = '';
    if (term !== 'All') { params.push(term); fCond += ` AND term = $${params.length}`; pCond += ` AND term = $${params.length}`; }
    if (feeItemId) { params.push(parseInt(feeItemId)); fCond += ` AND fee_item_id = $${params.length}`; pCond += ` AND COALESCE(fee_item_id, $2) = $${params.length}`; }
    const conditions = ['e.academic_year = $1', '(s.student_id IS NOT NULL OR p.paid IS NOT NULL)'];
    if (studentId) { params.push(studentId); conditions.push(`e.student_id = $${params.length}`); }
    if (gradeLevel) { params.push(parseInt(gradeLevel)); conditions.push(`e.grade_level = $${params.length}`); }
    if (className) { params.push(className); conditions.push(`LOWER(e.class_name) = LOWER($${params.length})`); }
    const summary = await sql(`
      SELECT e.student_id,
             COALESCE(s.full_name, e.full_name) AS full_name,
             e.grade_level, e.class_name,
             COALESCE(s.status, 'deleted') AS status,
             COALESCE(f.amount, 0)::float AS expected,
             COALESCE(p.paid, 0)::float AS paid
      FROM student_enrollments e
      LEFT JOIN students s ON s.student_id = e.student_id
      LEFT JOIN (
        SELECT grade_level, SUM(amount) AS amount FROM fee_structures
        WHERE academic_year = $1 ${fCond} AND $2::int IS NOT NULL
        GROUP BY grade_level
      ) f ON f.grade_level = e.grade_level
      LEFT JOIN (
        SELECT student_id, SUM(amount) AS paid FROM fee_payments
        WHERE academic_year = $1 AND voided = FALSE ${pCond}
        GROUP BY student_id
      ) p ON p.student_id = e.student_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY e.grade_level, e.class_name, full_name
    `, params);
    return json({ success: true, summary });
  } catch (err) {
    console.error('get-fee-summary error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ===========================================================================
// TEACHER ACCESS LINKS (admin creates, sets expiry, can cancel)
// ===========================================================================
function hashKey(k) { return crypto.createHash('sha256').update(String(k)).digest('hex'); }

// staff-links (GET) — admin
async function staffLinks(sql) {
  try {
    const links = await sql`
      SELECT l.id, l.teacher_id, t.full_name, t.username, l.revoked, l.created_by,
             to_char(l.created_at, 'DD/MM/YYYY HH24:MI') AS created,
             to_char(l.expires_at, 'DD Mon YYYY') AS expires,
             to_char(l.last_used_at, 'DD/MM/YYYY HH24:MI') AS last_used,
             (l.expires_at > NOW()) AS not_expired
      FROM staff_links l JOIN teachers t ON t.id = l.teacher_id
      ORDER BY l.created_at DESC LIMIT 300`;
    return json({ success: true, links });
  } catch (err) {
    console.error('staff-links error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// create-staff-link (POST { teacherId, validUntil: 'YYYY-MM-DD' }) — admin.
// Returns the link key ONCE (only its hash is stored).
async function createStaffLink(sql, event, auth) {
  try {
    const { teacherId, validUntil } = JSON.parse(event.body || '{}');
    if (!teacherId || !/^\d{4}-\d{2}-\d{2}$/.test(validUntil || '')) return json({ error: 'Teacher and a valid end date are required' }, 400);
    const expires = new Date(validUntil + 'T23:59:59Z');
    if (isNaN(expires.getTime()) || expires.getTime() <= Date.now()) return json({ error: 'The end date must be today or later' }, 400);
    if (expires.getTime() > Date.now() + 400 * 24 * 3600 * 1000) return json({ error: 'A link can be valid for at most about one year' }, 400);
    const t = await sql`SELECT id, full_name, username, active FROM teachers WHERE id = ${parseInt(teacherId)}`;
    if (!t.length) return json({ success: false, error: 'Teacher not found' }, 404);
    if (!t[0].active) return json({ success: false, error: 'This teacher is disabled. Enable them first.' }, 400);
    const key = crypto.randomBytes(24).toString('base64url');
    const rows = await sql`
      INSERT INTO staff_links (teacher_id, key_hash, expires_at, created_by)
      VALUES (${t[0].id}, ${hashKey(key)}, ${expires.toISOString()}, ${auth.sub}) RETURNING id`;
    return json({ success: true, id: rows[0].id, key, validUntil, teacher: t[0].full_name, username: t[0].username });
  } catch (err) {
    console.error('create-staff-link error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// revoke-staff-link (POST { id }) — admin. Stops the link immediately.
async function revokeStaffLink(sql, event, auth) {
  try {
    const { id } = JSON.parse(event.body || '{}');
    if (!id) return json({ error: 'id is required' }, 400);
    const rows = await sql`UPDATE staff_links SET revoked = TRUE, revoked_at = NOW(), revoked_by = ${auth.sub} WHERE id = ${parseInt(id)} AND revoked = FALSE RETURNING id`;
    if (!rows.length) return json({ success: false, error: 'Link not found or already cancelled' }, 404);
    return json({ success: true, message: 'Link cancelled — the teacher can no longer use it.' });
  } catch (err) {
    console.error('revoke-staff-link error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// delete-teacher (POST { id }) — admin. Removes the account, its class
// assignments and access links. Scores/attendance the teacher entered are KEPT.
async function deleteTeacher(sql, event) {
  try {
    const { id } = JSON.parse(event.body || '{}');
    if (!id) return json({ error: 'id is required' }, 400);
    const t = await sql`SELECT id, full_name FROM teachers WHERE id = ${parseInt(id)}`;
    if (!t.length) return json({ success: false, error: 'Teacher not found' }, 404);
    await sql`DELETE FROM staff_links WHERE teacher_id = ${t[0].id}`;
    await sql`DELETE FROM teacher_assignments WHERE teacher_id = ${t[0].id}`;
    await sql`DELETE FROM teachers WHERE id = ${t[0].id}`;
    return json({ success: true, message: `${t[0].full_name} deleted. Scores and attendance they entered are kept.` });
  } catch (err) {
    console.error('delete-teacher error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// delete-staff-link (POST { id } or { clearOld: true }) — admin.
// Only expired or cancelled links can be deleted (cancel an active link first).
async function deleteStaffLink(sql, event) {
  try {
    const { id, clearOld } = JSON.parse(event.body || '{}');
    if (clearOld) {
      const rows = await sql`DELETE FROM staff_links WHERE revoked = TRUE OR expires_at <= NOW() RETURNING id`;
      return json({ success: true, message: rows.length + ' old link(s) deleted.' });
    }
    if (!id) return json({ error: 'id is required' }, 400);
    const rows = await sql`DELETE FROM staff_links WHERE id = ${parseInt(id)} AND (revoked = TRUE OR expires_at <= NOW()) RETURNING id`;
    if (!rows.length) return json({ success: false, error: 'Only expired or cancelled links can be deleted. Cancel it first.' }, 400);
    return json({ success: true, message: 'Link deleted.' });
  } catch (err) {
    console.error('delete-staff-link error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ===========================================================================
// WEBSITE CONTENT: slideshow + news
// ===========================================================================
const IMAGE_PATH_RE = /^[A-Za-z0-9 _.()\-]+\.(jpe?g|png|webp|gif)$/i;
const NEWS_CATEGORIES = ['Announcement', 'Event', 'Competition', 'Achievement', 'Sports', 'General'];
function imageUrl(mediaId, imagePath) { return mediaId ? '/api/image?id=' + mediaId : (imagePath ? '/' + String(imagePath).replace(/^\/+/, '') : null); }

// image (GET ?id) — public. Serves an uploaded picture, cached by the browser for a year.
async function getImage(sql, event) {
  try {
    const id = parseInt((event.queryStringParameters || {}).id);
    if (!id) return { statusCode: 400, headers: { 'Content-Type': 'text/plain' }, body: 'id required' };
    const rows = await sql`SELECT mime, data FROM media WHERE id = ${id}`;
    if (!rows.length) return { statusCode: 404, headers: { 'Content-Type': 'text/plain' }, body: 'Not found' };
    return {
      statusCode: 200,
      headers: { 'Content-Type': rows[0].mime, 'Cache-Control': 'public, max-age=31536000, immutable', 'Access-Control-Allow-Origin': '*' },
      body: rows[0].data,
      isBase64Encoded: true,
    };
  } catch (err) {
    console.error('image error:', err);
    return { statusCode: 500, headers: { 'Content-Type': 'text/plain' }, body: 'Server error' };
  }
}

// upload-image (POST { dataUrl }) — admin. Stores a picture, returns its id + url.
async function uploadImage(sql, event, auth) {
  try {
    const { dataUrl } = JSON.parse(event.body || '{}');
    const m = /^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
    if (!m) return json({ error: 'Please upload a JPG, PNG, WEBP or GIF picture' }, 400);
    if (m[2].length > 3200000) return json({ error: 'Picture is too large (max about 2 MB after compression)' }, 400);
    const size = Math.floor(m[2].length * 3 / 4);
    const rows = await sql`INSERT INTO media (mime, data, size, uploaded_by) VALUES (${m[1]}, ${m[2]}, ${size}, ${auth.sub}) RETURNING id`;
    return json({ success: true, id: rows[0].id, url: imageUrl(rows[0].id) });
  } catch (err) {
    console.error('upload-image error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// site-content (GET) — public. Everything the public home page and news tab need.
async function siteContent(sql) {
  try {
    const slides = await sql`SELECT id, caption, media_id, image_path FROM slides WHERE active = TRUE ORDER BY sort_order, id`;
    const news = await sql`
      SELECT id, title, category, body, media_id, image_path, featured, author,
             to_char(published_at, 'DD Mon YYYY') AS date
      FROM news_posts WHERE status = 'published'
      ORDER BY featured DESC, published_at DESC, id DESC
      LIMIT 30
    `;
    return json({
      success: true,
      slides: slides.map(s => ({ id: s.id, caption: s.caption, url: imageUrl(s.media_id, s.image_path) })),
      news: news.map(n => ({ id: n.id, title: n.title, category: n.category, body: n.body, featured: n.featured, author: n.author, date: n.date, image: imageUrl(n.media_id, n.image_path) })),
    });
  } catch (err) {
    // Tables not created yet -> the site just keeps its built-in pictures/news.
    console.error('site-content error:', err);
    return json({ success: false, slides: [], news: [] });
  }
}

// admin-slides (GET) — admin. All slides, including removed ones.
async function adminSlides(sql) {
  try {
    const rows = await sql`
      SELECT id, caption, media_id, image_path, sort_order, active, created_by,
             to_char(created_at, 'DD/MM/YYYY') AS created
      FROM slides ORDER BY active DESC, sort_order, id`;
    return json({ success: true, slides: rows.map(r => Object.assign({}, r, { url: imageUrl(r.media_id, r.image_path) })) });
  } catch (err) {
    console.error('admin-slides error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-slide (POST { action: add | update | remove | restore | reorder, ... }) — admin
async function saveSlide(sql, event, auth) {
  try {
    const b = JSON.parse(event.body || '{}');
    const nextOrder = async () => (await sql`SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM slides WHERE active = TRUE`)[0].n;
    if (b.action === 'add') {
      const mediaId = b.mediaId ? parseInt(b.mediaId) : null;
      const imagePath = b.imagePath ? String(b.imagePath) : null;
      if (!mediaId && !imagePath) return json({ error: 'A picture is required' }, 400);
      if (imagePath && !IMAGE_PATH_RE.test(imagePath)) return json({ error: 'Invalid picture name' }, 400);
      const rows = await sql`
        INSERT INTO slides (media_id, image_path, caption, sort_order, created_by)
        VALUES (${mediaId}, ${imagePath}, ${b.caption || null}, ${await nextOrder()}, ${auth.sub}) RETURNING id`;
      return json({ success: true, id: rows[0].id, message: 'Picture added to the slideshow' });
    }
    if (b.action === 'update') {
      const rows = await sql`UPDATE slides SET caption = ${b.caption || null}, updated_at = NOW() WHERE id = ${parseInt(b.id)} RETURNING id`;
      if (!rows.length) return json({ success: false, error: 'Slide not found' }, 404);
      return json({ success: true, message: 'Caption saved' });
    }
    if (b.action === 'remove' || b.action === 'restore') {
      const active = b.action === 'restore';
      const order = active ? await nextOrder() : 0;
      const rows = await sql`
        UPDATE slides SET active = ${active}, sort_order = CASE WHEN ${active} THEN ${order} ELSE sort_order END, updated_at = NOW()
        WHERE id = ${parseInt(b.id)} RETURNING id`;
      if (!rows.length) return json({ success: false, error: 'Slide not found' }, 404);
      return json({ success: true, message: active ? 'Picture restored to the slideshow' : 'Picture removed from the slideshow (kept in Removed)' });
    }
    if (b.action === 'reorder') {
      if (!Array.isArray(b.ids) || !b.ids.length) return json({ error: 'ids required' }, 400);
      const ids = b.ids.map(x => parseInt(x));
      await sql`
        UPDATE slides s SET sort_order = o.ord, updated_at = NOW()
        FROM unnest(${ids}::int[]) WITH ORDINALITY AS o(id, ord)
        WHERE s.id = o.id`;
      return json({ success: true, message: 'Order saved' });
    }
    return json({ error: 'Unknown action' }, 400);
  } catch (err) {
    console.error('save-slide error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// admin-news (GET) — admin. Every post ever made, with number of versions.
async function adminNews(sql) {
  try {
    const rows = await sql`
      SELECT p.id, p.title, p.category, p.body, p.media_id, p.image_path, p.featured, p.status, p.author,
             to_char(p.published_at, 'DD/MM/YYYY') AS published, to_char(p.created_at, 'DD/MM/YYYY') AS created,
             to_char(p.updated_at, 'DD/MM/YYYY HH24:MI') AS updated,
             (SELECT COUNT(*)::int FROM news_history h WHERE h.post_id = p.id) AS versions
      FROM news_posts p ORDER BY p.created_at DESC, p.id DESC`;
    return json({ success: true, posts: rows.map(r => Object.assign({}, r, { image: imageUrl(r.media_id, r.image_path) })) });
  } catch (err) {
    console.error('admin-news error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

async function snapshotNews(sql, postId, action, actor) {
  await sql`
    INSERT INTO news_history (post_id, title, category, body, media_id, image_path, featured, status, action, edited_by)
    SELECT id, title, category, body, media_id, image_path, featured, status, ${action}, ${actor}
    FROM news_posts WHERE id = ${postId}`;
}

// save-news (POST { id?, title, category, body, status, featured, mediaId, imagePath }) — admin
async function saveNews(sql, event, auth) {
  try {
    const b = JSON.parse(event.body || '{}');
    const title = String(b.title || '').trim();
    const body = String(b.body || '').trim();
    if (!title || !body) return json({ error: 'Title and story are required' }, 400);
    if (title.length > 200) return json({ error: 'Title is too long (max 200 characters)' }, 400);
    const category = NEWS_CATEGORIES.includes(b.category) ? b.category : 'General';
    const status = b.status === 'hidden' ? 'hidden' : 'published';
    const featured = !!b.featured;
    const mediaId = b.mediaId ? parseInt(b.mediaId) : null;
    const imagePath = b.imagePath && IMAGE_PATH_RE.test(String(b.imagePath)) ? String(b.imagePath) : null;
    let id = b.id ? parseInt(b.id) : null;
    if (id) {
      const rows = await sql`
        UPDATE news_posts SET title = ${title}, category = ${category}, body = ${body}, status = ${status},
          featured = ${featured}, media_id = ${mediaId}, image_path = ${imagePath},
          published_at = CASE WHEN ${status} = 'published' AND published_at IS NULL THEN NOW() ELSE published_at END,
          updated_at = NOW(), updated_by = ${auth.sub}
        WHERE id = ${id} RETURNING id`;
      if (!rows.length) return json({ success: false, error: 'Post not found' }, 404);
    } else {
      const rows = await sql`
        INSERT INTO news_posts (title, category, body, status, featured, media_id, image_path, author, published_at, created_by, updated_by)
        VALUES (${title}, ${category}, ${body}, ${status}, ${featured}, ${mediaId}, ${imagePath}, 'Administration',
                CASE WHEN ${status} = 'published' THEN NOW() ELSE NULL END, ${auth.sub}, ${auth.sub})
        RETURNING id`;
      id = rows[0].id;
    }
    if (featured) await sql`UPDATE news_posts SET featured = FALSE WHERE id <> ${id} AND featured = TRUE`;
    await snapshotNews(sql, id, b.id ? 'edited' : 'created', auth.sub);
    return json({ success: true, id, message: b.id ? 'Post updated' : (status === 'published' ? 'Post published' : 'Post saved as hidden draft') });
  } catch (err) {
    console.error('save-news error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// news-status (POST { id, status: published | hidden }) — admin. Posts are never deleted.
async function newsStatus(sql, event, auth) {
  try {
    const { id, status } = JSON.parse(event.body || '{}');
    if (!id || !['published', 'hidden'].includes(status)) return json({ error: 'id and status are required' }, 400);
    const rows = await sql`
      UPDATE news_posts SET status = ${status}, updated_at = NOW(), updated_by = ${auth.sub},
        published_at = CASE WHEN ${status} = 'published' AND published_at IS NULL THEN NOW() ELSE published_at END
      WHERE id = ${parseInt(id)} RETURNING id`;
    if (!rows.length) return json({ success: false, error: 'Post not found' }, 404);
    await snapshotNews(sql, parseInt(id), status === 'hidden' ? 'hidden' : 'published', auth.sub);
    return json({ success: true, message: status === 'hidden' ? 'Post hidden from the website (kept in history)' : 'Post is visible on the website' });
  } catch (err) {
    console.error('news-status error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// news-history (GET ?id) — admin. Every version of a post.
async function newsHistory(sql, event) {
  try {
    const id = parseInt((event.queryStringParameters || {}).id);
    if (!id) return json({ error: 'id is required' }, 400);
    const rows = await sql`
      SELECT id, title, category, body, status, featured, action, edited_by,
             to_char(edited_at, 'DD/MM/YYYY HH24:MI') AS edited, media_id, image_path
      FROM news_history WHERE post_id = ${id} ORDER BY edited_at DESC, id DESC`;
    return json({ success: true, versions: rows.map(r => Object.assign({}, r, { image: imageUrl(r.media_id, r.image_path) })) });
  } catch (err) {
    console.error('news-history error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ===========================================================================
// TEACHERS & ATTENDANCE
// ===========================================================================
const TEACHER_TOKEN_HOURS = 12;
const ATTENDANCE_STATUSES = ['present', 'absent', 'late', 'excused'];

function todayISO() { return new Date().toISOString().slice(0, 10); }
function normClass(c) { return String(c || '').trim().toUpperCase(); }
function serverScoreToGrade(score) {
  if (score >= 85) return 'A1';
  if (score >= 75) return 'B2';
  if (score >= 65) return 'B3';
  if (score >= 60) return 'C4';
  if (score >= 55) return 'C5';
  if (score >= 50) return 'C6';
  if (score >= 45) return 'D7';
  if (score >= 40) return 'E8';
  return 'F9';
}
function actorName(auth) { return (auth.role === 'teacher' ? 'teacher:' : auth.role === 'owner' ? 'owner:' : 'admin:') + auth.sub; }

const ACTION_INFO = {
  'admin-login': ['Admin logged in', 'login'], 'student-login': ['Student logged in', 'login'], 'teacher-login': ['Teacher logged in', 'login'], 'owner-login': ['Owner logged in', 'login'],
  'change-admin-password': ['Changed the admin password', 'settings'], 'add-student': ['Added a student', 'students'],
  'update-student': ['Edited a student', 'students'], 'archive-student': ['Archived / restored a student', 'students'],
  'promote-students': ['Promoted students to a new year', 'students'], 'set-repeat': ['Marked a student to repeat', 'students'],
  'demote-student': ['Moved a student down a grade', 'students'], 'reset-password': ['Reset a student password', 'students'],
  'admin-upload-photo': ['Changed a student photo', 'students'], 'block-upload': ['Changed photo-upload permission', 'settings'],
  'add-marks': ['Entered / changed marks', 'results'], 'delete-results': ['Deleted results', 'results'],
  'save-remarks': ['Saved report remarks', 'results'], 'save-class-scores': ['Saved class scores', 'results'],
  'record-payment': ['Recorded a payment', 'finance'], 'void-payment': ['VOIDED a payment', 'finance'],
  'save-fee-structure': ['Set a fee amount', 'finance'], 'save-fee-item': ['Added / edited a fee item', 'finance'],
  'delete-staff-link': ['Deleted a teacher link', 'teachers'], 'create-staff-link': ['Created a teacher link', 'teachers'],
  'revoke-staff-link': ['Cancelled a teacher link', 'teachers'], 'save-teacher': ['Created / edited a teacher', 'teachers'],
  'delete-teacher': ['Deleted a teacher', 'teachers'], 'teacher-assignment': ['Changed a teacher assignment', 'teachers'],
  'save-attendance': ['Saved an attendance register', 'attendance'], 'save-holiday': ['Declared a public holiday', 'attendance'],
  'delete-holiday': ['Removed a public holiday', 'attendance'], 'save-term-dates': ['Set term dates', 'attendance'],
  'save-slide': ['Changed the slideshow', 'website'], 'save-news': ['Changed a news post', 'website'],
  'news-status': ['Showed / hid a news post', 'website'], 'upload-image': ['Uploaded a picture', 'website'],
  'admin-view': ['Opened a page', 'view'],
  'sds-set-admin-password': ['Admin password changed remotely (SDS)', 'settings'],
};
function clientIp(event) {
  const h = event.headers || {};
  return (h['x-nf-client-connection-ip'] || h['client-ip'] || (h['x-forwarded-for'] || '').split(',')[0] || '').trim() || null;
}
function shortDevice(event) {
  const ua = (event.headers || {})['user-agent'] || '';
  const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad|iOS/.test(ua) ? 'iPhone/iPad' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : '';
  const br = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera' : /Chrome/.test(ua) ? 'Chrome' : /Safari/.test(ua) ? 'Safari' : /Firefox/.test(ua) ? 'Firefox' : '';
  return [br, os].filter(Boolean).join(' / ') || (ua ? ua.slice(0, 40) : null);
}
// Turn an IP into "City, Region, Country · Network". Cached; failures are ignored.
const IP_CACHE = new Map();
const PRIVATE_IP = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fc|fd)/i;
async function ipLocation(ip) {
  if (!ip || PRIVATE_IP.test(ip)) return null;
  if (IP_CACHE.has(ip)) return IP_CACHE.get(ip);
  let loc = null;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2500);
    const res = await fetch('https://ipwho.is/' + encodeURIComponent(ip) + '?fields=success,city,region,country,connection', { signal: ctrl.signal });
    clearTimeout(timer);
    const d = await res.json();
    if (d && d.success) {
      const place = [d.city, d.region, d.country].filter(Boolean).join(', ');
      const net = d.connection && (d.connection.isp || d.connection.org);
      loc = [place, net].filter(Boolean).join(' · ') || null;
    }
  } catch (e) { loc = null; }
  if (IP_CACHE.size > 500) IP_CACHE.clear();
  IP_CACHE.set(ip, loc);
  return loc;
}
async function logActivity(sql, event, o) {
  try {
    const info = ACTION_INFO[o.action] || [o.action, 'other'];
    const ip = clientIp(event);
    // Location lookup only for logins and data changes, to stay well under the free quota.
    const loc = (info[1] === 'login' || (o.role !== 'student' && info[1] !== 'view')) ? await ipLocation(ip) : null;
    await sql`INSERT INTO activity_log (actor_role, actor_name, action, category, detail, target, method, route, ok, ip, device, location)
      VALUES (${o.role || null}, ${o.name || null}, ${info[0]}, ${info[1]}, ${o.detail || null}, ${o.target || null},
              ${event.httpMethod || null}, ${o.action}, ${o.ok !== false}, ${ip}, ${shortDevice(event)}, ${loc || null})`;
  } catch (err) { console.error('activity-log write failed:', err.message); }
}
function logDetailFor(route, event) {
  let b = {}; try { b = JSON.parse(event.body || '{}'); } catch (e) {}
  switch (route) {
    case 'add-student': case 'update-student': case 'reset-password': case 'archive-student':
    case 'set-repeat': case 'demote-student': case 'admin-upload-photo': return b.studentId ? 'Student ' + b.studentId : null;
    case 'add-marks': return b.studentId ? b.studentId + ' / ' + (b.subject || '') + ' = ' + (b.score != null ? b.score : '') : null;
    case 'delete-results': return b.studentId ? 'Student ' + b.studentId : null;
    case 'record-payment': return b.studentId ? b.studentId + ' / ' + (b.amount != null ? 'D' + b.amount : '') : null;
    case 'void-payment': return b.reason ? 'Reason: ' + b.reason : (b.id ? 'Payment #' + b.id : null);
    case 'save-fee-structure': return 'Grade ' + (b.gradeLevel || '') + ' / ' + (b.term || '');
    case 'save-holiday': return b.name ? b.name + (b.from ? ' (' + b.from + (b.to ? ' to ' + b.to : '') + ')' : '') : null;
    case 'create-staff-link': case 'save-teacher': case 'delete-teacher': return b.teacherId ? 'Teacher #' + b.teacherId : (b.id ? 'Teacher #' + b.id : (b.username || null));
    case 'save-attendance': return 'Grade ' + (b.gradeLevel || '') + ' / ' + (b.className || '') + ' / ' + (b.date || '');
    case 'admin-view': return b.label || b.tab || null;
    default: return null;
  }
}

// Admin can access any class. A teacher only classes (and subjects) assigned
// to them for that academic year, and only while their account is active.
async function staffCanAccessClass(sql, auth, academicYear, gradeLevel, className, subject) {
  if (!auth) return false;
  if (auth.role === 'admin') return true;
  if (auth.role !== 'teacher') return false;
  const rows = subject
    ? await sql`
        SELECT 1 FROM teacher_assignments a JOIN teachers t ON t.id = a.teacher_id
        WHERE a.teacher_id = ${auth.tid} AND t.active = TRUE
          AND a.academic_year = ${academicYear} AND a.grade_level = ${parseInt(gradeLevel)}
          AND UPPER(a.class_name) = ${normClass(className)} AND a.subject = ${subject}
        LIMIT 1`
    : await sql`
        SELECT 1 FROM teacher_assignments a JOIN teachers t ON t.id = a.teacher_id
        WHERE a.teacher_id = ${auth.tid} AND t.active = TRUE
          AND a.academic_year = ${academicYear} AND a.grade_level = ${parseInt(gradeLevel)}
          AND UPPER(a.class_name) = ${normClass(className)}
        LIMIT 1`;
  return rows.length > 0;
}

// Students in a class for a given academic year (uses that year's enrollment).
async function loadClassStudents(sql, academicYear, gradeLevel, className) {
  return sql`
    SELECT e.student_id, COALESCE(s.full_name, e.full_name) AS full_name, e.class_name, s.gender
    FROM student_enrollments e
    JOIN students s ON s.student_id = e.student_id
    WHERE e.academic_year = ${academicYear}
      AND e.grade_level = ${parseInt(gradeLevel)}
      AND UPPER(e.class_name) = ${normClass(className)}
      AND s.status <> 'archived'
    ORDER BY full_name
  `;
}

// teacher-login (POST) — public
async function teacherLogin(sql, event) {
  try {
    const { username, password, key: linkKey } = JSON.parse(event.body || '{}');
    if (!username || !password) return json({ error: 'Username and password are required' }, 400);
    if (!linkKey) return json({ success: false, error: 'Please open the access link your school admin sent you.' }, 403);
    const link = (await sql`SELECT id, teacher_id, revoked, expires_at FROM staff_links WHERE key_hash = ${hashKey(linkKey)} LIMIT 1`)[0];
    if (!link) return json({ success: false, error: 'This access link is not valid. Ask the admin for a new link.' }, 403);
    if (link.revoked) return json({ success: false, error: 'This access link was cancelled by the admin.' }, 403);
    if (new Date(link.expires_at).getTime() <= Date.now()) return json({ success: false, error: 'This access link has expired. Ask the admin for a new link.' }, 403);
    const key = 'teacher:' + String(username).toLowerCase();
    const mins = await lockMinutesLeft(sql, key);
    if (mins) return json({ success: false, error: `Too many failed attempts. Try again in ${mins} minute(s).` }, 429);
    const rows = await sql`SELECT id, username, full_name, password, active FROM teachers WHERE LOWER(username) = LOWER(${username}) LIMIT 1`;
    const check = rows.length ? checkPassword(password, rows[0].password) : { ok: false };
    if (!check.ok) {
      await recordFail(sql, key);
      return json({ success: false, error: 'Incorrect username or password' }, 401);
    }
    if (!rows[0].active) return json({ success: false, error: 'This teacher account has been disabled. Please contact the school admin.' }, 403);
    await clearFails(sql, key);
    const t = rows[0];
    if (link.teacher_id !== t.id) return json({ success: false, error: 'This access link belongs to another teacher. Use your own link.' }, 403);
    await sql`UPDATE staff_links SET last_used_at = NOW() WHERE id = ${link.id}`;
    // The login lasts until the link expires (the link is re-checked on every request).
    const token = signToken({ role: 'teacher', sub: t.username, tid: t.id, lid: link.id, exp: new Date(link.expires_at).getTime() });
    return json({ success: true, token, teacher: { id: t.id, username: t.username, full_name: t.full_name }, accessUntil: link.expires_at });
  } catch (err) {
    console.error('teacher-login error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// teacher-me (GET) — teacher: own profile + assigned classes/subjects
async function teacherMe(sql, event, auth) {
  try {
    if (auth.role !== 'teacher') return json({ error: 'Teachers only' }, 400);
    const t = await sql`SELECT id, username, full_name, phone, active FROM teachers WHERE id = ${auth.tid} LIMIT 1`;
    if (!t.length || !t[0].active) return json({ success: false, error: 'This teacher account is disabled or no longer exists.' }, 403);
    const assignments = await sql`
      SELECT id, academic_year, grade_level, class_name, subject
      FROM teacher_assignments WHERE teacher_id = ${auth.tid}
      ORDER BY academic_year DESC, grade_level, class_name, subject
    `;
    const l = auth.lid ? await sql`SELECT to_char(expires_at, 'DD Mon YYYY') AS until FROM staff_links WHERE id = ${auth.lid}` : [];
    return json({ success: true, teacher: t[0], assignments, accessUntil: l.length ? l[0].until : null });
  } catch (err) {
    console.error('teacher-me error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// get-class-scores (GET ?academicYear&term&gradeLevel&className&subject) — admin or assigned teacher
async function getClassScores(sql, event, auth) {
  try {
    const { academicYear, term, gradeLevel, className, subject } = event.queryStringParameters || {};
    if (!academicYear || !term || !gradeLevel || !className || !subject) {
      return json({ error: 'academicYear, term, gradeLevel, className and subject are required' }, 400);
    }
    if (!(await staffCanAccessClass(sql, auth, academicYear, gradeLevel, className, subject))) {
      return json({ success: false, error: 'You are not assigned to this class and subject.' }, 403);
    }
    const students = await loadClassStudents(sql, academicYear, gradeLevel, className);
    const ids = students.map(s => s.student_id);
    const scores = ids.length ? await sql`
      SELECT student_id, score, grade, entered_by, to_char(entered_at, 'DD/MM/YYYY HH24:MI') AS entered_at
      FROM results
      WHERE academic_year = ${academicYear} AND term = ${term} AND subject = ${subject}
        AND student_id = ANY(${ids})
    ` : [];
    const byId = {};
    scores.forEach(r => { byId[r.student_id] = r; });
    return json({
      success: true,
      students: students.map(s => Object.assign({}, s, {
        score: byId[s.student_id] ? byId[s.student_id].score : null,
        grade: byId[s.student_id] ? byId[s.student_id].grade : null,
        entered_by: byId[s.student_id] ? byId[s.student_id].entered_by : null,
        entered_at: byId[s.student_id] ? byId[s.student_id].entered_at : null,
      })),
    });
  } catch (err) {
    console.error('get-class-scores error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-class-scores (POST) — admin or assigned teacher. Saves a whole class at once.
// Old values are copied to results_archive before being overwritten.
async function saveClassScores(sql, event, auth) {
  try {
    const { academicYear, term, gradeLevel, className, subject, scores } = JSON.parse(event.body || '{}');
    if (!academicYear || !term || !gradeLevel || !className || !subject || !Array.isArray(scores)) {
      return json({ error: 'academicYear, term, gradeLevel, className, subject and scores are required' }, 400);
    }
    if (!(await staffCanAccessClass(sql, auth, academicYear, gradeLevel, className, subject))) {
      return json({ success: false, error: 'You are not assigned to this class and subject.' }, 403);
    }
    const students = await loadClassStudents(sql, academicYear, gradeLevel, className);
    const classOf = {};
    students.forEach(s => { classOf[s.student_id] = s.class_name; });

    const ids = [], vals = [], grades = [], classes = [];
    for (const entry of scores) {
      const sid = entry && entry.studentId;
      const score = Number(entry && entry.score);
      if (!sid || !(sid in classOf)) return json({ success: false, error: `Student ${sid} is not in this class.` }, 400);
      if (!Number.isInteger(score) || score < 0 || score > 100) return json({ success: false, error: `Invalid score for ${sid} (must be a whole number 0-100).` }, 400);
      ids.push(sid); vals.push(score); grades.push(serverScoreToGrade(score)); classes.push(classOf[sid]);
    }
    if (!ids.length) return json({ success: false, error: 'No scores to save' }, 400);
    const actor = actorName(auth);

    await sql`
      INSERT INTO results_archive (student_id, subject, score, grade, academic_year, term, grade_level, class_name, action, action_by)
      SELECT r.student_id, r.subject, r.score, r.grade, r.academic_year, r.term, r.grade_level, r.class_name, 'overwritten', ${actor}
      FROM results r
      JOIN unnest(${ids}::text[], ${vals}::int[]) AS n(student_id, score) ON n.student_id = r.student_id
      WHERE r.subject = ${subject} AND r.academic_year = ${academicYear} AND r.term = ${term}
        AND r.score IS DISTINCT FROM n.score
    `;
    await sql`
      INSERT INTO results (student_id, subject, score, grade, academic_year, term, grade_level, class_name, entered_by, entered_at)
      SELECT n.student_id, ${subject}, n.score, n.grade, ${academicYear}, ${term}, ${parseInt(gradeLevel)}, n.class_name, ${actor}, NOW()
      FROM unnest(${ids}::text[], ${vals}::int[], ${grades}::text[], ${classes}::text[]) AS n(student_id, score, grade, class_name)
      ON CONFLICT (student_id, subject, academic_year, term)
      DO UPDATE SET
        score = EXCLUDED.score, grade = EXCLUDED.grade,
        grade_level = EXCLUDED.grade_level, class_name = EXCLUDED.class_name,
        entered_by = EXCLUDED.entered_by, entered_at = EXCLUDED.entered_at
    `;
    return json({ success: true, message: `Saved ${ids.length} score(s) for ${subject}.` });
  } catch (err) {
    console.error('save-class-scores error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// get-attendance (GET ?date&academicYear&gradeLevel&className) — admin or assigned teacher
async function getAttendance(sql, event, auth) {
  try {
    const { date, academicYear, gradeLevel, className } = event.queryStringParameters || {};
    if (!date || !academicYear || !gradeLevel || !className) {
      return json({ error: 'date, academicYear, gradeLevel and className are required' }, 400);
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ error: 'date must look like 2026-10-17' }, 400);
    if (!(await staffCanAccessClass(sql, auth, academicYear, gradeLevel, className))) {
      return json({ success: false, error: 'You are not assigned to this class.' }, 403);
    }
    const students = await sql`
      SELECT e.student_id, COALESCE(s.full_name, e.full_name) AS full_name, e.class_name,
             a.status, a.marked_by, to_char(a.marked_at, 'DD/MM HH24:MI') AS marked_at
      FROM student_enrollments e
      JOIN students s ON s.student_id = e.student_id
      LEFT JOIN attendance a ON a.student_id = e.student_id AND a.attendance_date = ${date}::date
      WHERE e.academic_year = ${academicYear}
        AND e.grade_level = ${parseInt(gradeLevel)}
        AND UPPER(e.class_name) = ${normClass(className)}
        AND s.status <> 'archived'
      ORDER BY full_name
    `;
    const hol = await sql`SELECT name FROM school_holidays WHERE holiday_date = ${date}::date`;
    return json({ success: true, date, today: todayISO(), students, holiday: hol.length ? hol[0].name : null });
  } catch (err) {
    console.error('get-attendance error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-attendance (POST) — admin (any date) or assigned teacher (today only)
async function saveAttendance(sql, event, auth) {
  try {
    const { date, academicYear, gradeLevel, className, records } = JSON.parse(event.body || '{}');
    if (!date || !academicYear || !gradeLevel || !className || !Array.isArray(records)) {
      return json({ error: 'date, academicYear, gradeLevel, className and records are required' }, 400);
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ error: 'date must look like 2026-10-17' }, 400);
    if (auth.role === 'teacher' && date !== todayISO()) {
      return json({ success: false, error: "Teachers can only mark today's register. Ask the admin to correct other days." }, 403);
    }
    if (!(await staffCanAccessClass(sql, auth, academicYear, gradeLevel, className))) {
      return json({ success: false, error: 'You are not assigned to this class.' }, 403);
    }
    const hol = await sql`SELECT name FROM school_holidays WHERE holiday_date = ${date}::date`;
    if (hol.length) return json({ success: false, holiday: hol[0].name, error: `${date} is a public holiday (${hol[0].name}). No register is needed.` }, 400);
    const students = await loadClassStudents(sql, academicYear, gradeLevel, className);
    const classOf = {};
    students.forEach(s => { classOf[s.student_id] = s.class_name; });
    const ids = [], statuses = [], classes = [];
    for (const r of records) {
      if (!r || !(r.studentId in classOf)) return json({ success: false, error: `Student ${r && r.studentId} is not in this class.` }, 400);
      if (!ATTENDANCE_STATUSES.includes(r.status)) return json({ success: false, error: `Invalid status for ${r.studentId}` }, 400);
      ids.push(r.studentId); statuses.push(r.status); classes.push(classOf[r.studentId]);
    }
    if (!ids.length) return json({ success: false, error: 'Mark at least one student' }, 400);
    // Corrections: keep the previous mark in attendance_history before it is replaced.
    await sql`
      INSERT INTO attendance_history (student_id, attendance_date, old_status, new_status, old_marked_by, changed_by)
      SELECT a.student_id, a.attendance_date, a.status, n.status, a.marked_by, ${actorName(auth)}
      FROM attendance a
      JOIN unnest(${ids}::text[], ${statuses}::text[]) AS n(student_id, status) ON n.student_id = a.student_id
      WHERE a.attendance_date = ${date}::date AND a.status <> n.status
    `;
    await sql`
      INSERT INTO attendance (student_id, attendance_date, academic_year, grade_level, class_name, status, marked_by, marked_at)
      SELECT n.student_id, ${date}::date, ${academicYear}, ${parseInt(gradeLevel)}, n.class_name, n.status, ${actorName(auth)}, NOW()
      FROM unnest(${ids}::text[], ${statuses}::text[], ${classes}::text[]) AS n(student_id, status, class_name)
      ON CONFLICT (student_id, attendance_date) DO UPDATE SET
        status = EXCLUDED.status, academic_year = EXCLUDED.academic_year,
        grade_level = EXCLUDED.grade_level, class_name = EXCLUDED.class_name,
        marked_by = EXCLUDED.marked_by, marked_at = EXCLUDED.marked_at
    `;
    return json({ success: true, message: `Register saved for ${ids.length} student(s) on ${date}.` });
  } catch (err) {
    console.error('save-attendance error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// attendance-report (GET ?academicYear&gradeLevel&className[&from&to]) — admin or assigned teacher
async function attendanceReport(sql, event, auth) {
  try {
    const { academicYear, gradeLevel, className, from, to } = event.queryStringParameters || {};
    if (!academicYear || !gradeLevel || !className) return json({ error: 'academicYear, gradeLevel and className are required' }, 400);
    if (!(await staffCanAccessClass(sql, auth, academicYear, gradeLevel, className))) {
      return json({ success: false, error: 'You are not assigned to this class.' }, 403);
    }
    const fromD = from && /^\d{4}-\d{2}-\d{2}$/.test(from) ? from : null;
    const toD = to && /^\d{4}-\d{2}-\d{2}$/.test(to) ? to : null;
    const rows = await sql`
      SELECT e.student_id, COALESCE(s.full_name, e.full_name) AS full_name, e.class_name,
             COUNT(a.id) FILTER (WHERE a.status = 'present')::int AS present,
             COUNT(a.id) FILTER (WHERE a.status = 'absent')::int  AS absent,
             COUNT(a.id) FILTER (WHERE a.status = 'late')::int    AS late,
             COUNT(a.id) FILTER (WHERE a.status = 'excused')::int AS excused,
             COUNT(a.id)::int AS days
      FROM student_enrollments e
      JOIN students s ON s.student_id = e.student_id
      LEFT JOIN attendance a ON a.student_id = e.student_id
        AND a.academic_year = e.academic_year
        AND (${fromD}::date IS NULL OR a.attendance_date >= ${fromD}::date)
        AND (${toD}::date IS NULL OR a.attendance_date <= ${toD}::date)
        AND NOT EXISTS (SELECT 1 FROM school_holidays h WHERE h.holiday_date = a.attendance_date)
      WHERE e.academic_year = ${academicYear}
        AND e.grade_level = ${parseInt(gradeLevel)}
        AND UPPER(e.class_name) = ${normClass(className)}
      GROUP BY e.student_id, s.full_name, e.full_name, e.class_name
      ORDER BY full_name
    `;
    return json({ success: true, rows });
  } catch (err) {
    console.error('attendance-report error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ===========================================================================
// PUBLIC HOLIDAYS + STUDENT / WHOLE-SCHOOL ATTENDANCE
// ===========================================================================
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

// get-holidays (GET ?from&to) — staff (teachers see them too)
async function getHolidays(sql, event) {
  try {
    const { from, to } = event.queryStringParameters || {};
    const f = from && ISO_DATE.test(from) ? from : null, t = to && ISO_DATE.test(to) ? to : null;
    const holidays = await sql`
      SELECT to_char(holiday_date, 'YYYY-MM-DD') AS date, to_char(holiday_date, 'Dy DD Mon YYYY') AS label, name, created_by
      FROM school_holidays
      WHERE (${f}::date IS NULL OR holiday_date >= ${f}::date) AND (${t}::date IS NULL OR holiday_date <= ${t}::date)
      ORDER BY holiday_date`;
    return json({ success: true, holidays });
  } catch (err) {
    console.error('get-holidays error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-holiday (POST { from, to?, name }) — admin. A range declares every day in it.
async function saveHoliday(sql, event, auth) {
  try {
    const { from, to, name } = JSON.parse(event.body || '{}');
    const nm = String(name || '').trim();
    if (!from || !ISO_DATE.test(from) || (to && !ISO_DATE.test(to))) return json({ error: 'Choose the holiday date' }, 400);
    if (!nm) return json({ error: 'Give the holiday a name (e.g. Independence Day)' }, 400);
    const end = to || from;
    const days = Math.round((new Date(end + 'T00:00:00Z') - new Date(from + 'T00:00:00Z')) / 86400000) + 1;
    if (days < 1) return json({ error: 'The end date must be on or after the start date' }, 400);
    if (days > 60) return json({ error: 'A holiday period can be at most 60 days' }, 400);
    const rows = await sql`
      INSERT INTO school_holidays (holiday_date, name, created_by)
      SELECT d::date, ${nm}, ${auth.sub} FROM generate_series(${from}::date, ${end}::date, interval '1 day') AS d
      ON CONFLICT (holiday_date) DO UPDATE SET name = EXCLUDED.name
      RETURNING holiday_date`;
    const marked = await sql`SELECT COUNT(*)::int AS n FROM attendance WHERE attendance_date BETWEEN ${from}::date AND ${end}::date`;
    return json({ success: true, days: rows.length,
      message: `${nm}: ${rows.length} day(s) declared a public holiday.` + (marked[0].n ? ` ${marked[0].n} register mark(s) already on those days are kept but no longer counted.` : '') });
  } catch (err) {
    console.error('save-holiday error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// delete-holiday (POST { date }) — admin. The day becomes a normal school day again.
async function deleteHoliday(sql, event) {
  try {
    const { date } = JSON.parse(event.body || '{}');
    if (!date || !ISO_DATE.test(date)) return json({ error: 'date is required' }, 400);
    const rows = await sql`DELETE FROM school_holidays WHERE holiday_date = ${date}::date RETURNING name`;
    if (!rows.length) return json({ success: false, error: 'Holiday not found' }, 404);
    return json({ success: true, message: `${date} is a school day again.` });
  } catch (err) {
    console.error('delete-holiday error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// student-attendance (GET ?studentId&academicYear[&from&to]) — admin
async function studentAttendance(sql, event) {
  try {
    const { studentId, academicYear, from, to } = event.queryStringParameters || {};
    if (!studentId || !academicYear) return json({ error: 'studentId and academicYear are required' }, 400);
    const f = from && ISO_DATE.test(from) ? from : null, t = to && ISO_DATE.test(to) ? to : null;
    const stu = await sql`
      SELECT s.student_id, s.full_name, e.grade_level, e.class_name
      FROM students s LEFT JOIN student_enrollments e ON e.student_id = s.student_id AND e.academic_year = ${academicYear}
      WHERE LOWER(s.student_id) = LOWER(${studentId})`;
    if (!stu.length) return json({ success: false, error: 'Student not found' }, 404);
    const id = stu[0].student_id;
    const records = await sql`
      SELECT to_char(a.attendance_date, 'YYYY-MM-DD') AS date, to_char(a.attendance_date, 'Dy DD Mon YYYY') AS label,
             to_char(a.attendance_date, 'YYYY-MM') AS month, a.status, a.marked_by
      FROM attendance a
      WHERE a.student_id = ${id} AND a.academic_year = ${academicYear}
        AND (${f}::date IS NULL OR a.attendance_date >= ${f}::date) AND (${t}::date IS NULL OR a.attendance_date <= ${t}::date)
        AND NOT EXISTS (SELECT 1 FROM school_holidays h WHERE h.holiday_date = a.attendance_date)
      ORDER BY a.attendance_date DESC`;
    const holidays = await sql`
      SELECT to_char(holiday_date, 'YYYY-MM-DD') AS date, name FROM school_holidays
      WHERE (${f}::date IS NULL OR holiday_date >= ${f}::date) AND (${t}::date IS NULL OR holiday_date <= ${t}::date)`;
    return json({ success: true, student: stu[0], records, holidays });
  } catch (err) {
    console.error('student-attendance error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// school-attendance (GET ?academicYear[&from&to]) — admin. Every class in one table + today's registers.
async function schoolAttendance(sql, event) {
  try {
    const { academicYear, from, to } = event.queryStringParameters || {};
    if (!academicYear) return json({ error: 'academicYear is required' }, 400);
    const f = from && ISO_DATE.test(from) ? from : null, t = to && ISO_DATE.test(to) ? to : null;
    const today = todayISO();
    const classes = await sql`
      WITH cls AS (
        SELECT e.grade_level, UPPER(e.class_name) AS class_key, MIN(e.class_name) AS class_name, COUNT(*)::int AS students
        FROM student_enrollments e JOIN students s ON s.student_id = e.student_id
        WHERE e.academic_year = ${academicYear} AND s.status <> 'archived' AND e.class_name IS NOT NULL
        GROUP BY e.grade_level, UPPER(e.class_name)
      ),
      att AS (
        SELECT a.grade_level, UPPER(a.class_name) AS class_key,
               COUNT(DISTINCT a.attendance_date)::int AS days_marked,
               COUNT(*) FILTER (WHERE a.status = 'present')::int AS present,
               COUNT(*) FILTER (WHERE a.status = 'absent')::int  AS absent,
               COUNT(*) FILTER (WHERE a.status = 'late')::int    AS late,
               COUNT(*) FILTER (WHERE a.status = 'excused')::int AS excused,
               COUNT(*)::int AS marks
        FROM attendance a
        WHERE a.academic_year = ${academicYear}
          AND (${f}::date IS NULL OR a.attendance_date >= ${f}::date) AND (${t}::date IS NULL OR a.attendance_date <= ${t}::date)
          AND NOT EXISTS (SELECT 1 FROM school_holidays h WHERE h.holiday_date = a.attendance_date)
        GROUP BY a.grade_level, UPPER(a.class_name)
      ),
      tod AS (
        SELECT a.grade_level, UPPER(a.class_name) AS class_key,
               COUNT(*) FILTER (WHERE a.status <> 'absent')::int AS here, COUNT(*) FILTER (WHERE a.status = 'absent')::int AS away
        FROM attendance a WHERE a.academic_year = ${academicYear} AND a.attendance_date = ${today}::date
        GROUP BY a.grade_level, UPPER(a.class_name)
      )
      SELECT c.grade_level, c.class_name, c.students,
             COALESCE(att.days_marked, 0) AS days_marked, COALESCE(att.present, 0) AS present, COALESCE(att.absent, 0) AS absent,
             COALESCE(att.late, 0) AS late, COALESCE(att.excused, 0) AS excused, COALESCE(att.marks, 0) AS marks,
             (tod.class_key IS NOT NULL) AS marked_today, COALESCE(tod.here, 0) AS today_present, COALESCE(tod.away, 0) AS today_absent
      FROM cls c
      LEFT JOIN att ON att.grade_level = c.grade_level AND att.class_key = c.class_key
      LEFT JOIN tod ON tod.grade_level = c.grade_level AND tod.class_key = c.class_key
      ORDER BY c.grade_level, c.class_name`;
    const hol = await sql`SELECT name FROM school_holidays WHERE holiday_date = ${today}::date`;
    return json({ success: true, today, todayHoliday: hol.length ? hol[0].name : null, classes });
  } catch (err) {
    console.error('school-attendance error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// get-term-dates (GET ?academicYear) — staff
async function getTermDates(sql, event) {
  try {
    const { academicYear } = event.queryStringParameters || {};
    if (!academicYear) return json({ error: 'academicYear is required' }, 400);
    const terms = await sql`
      SELECT term, to_char(start_date, 'YYYY-MM-DD') AS start, to_char(end_date, 'YYYY-MM-DD') AS "end"
      FROM term_dates WHERE academic_year = ${academicYear} ORDER BY term`;
    return json({ success: true, terms });
  } catch (err) {
    console.error('get-term-dates error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-term-dates (POST { academicYear, terms: [{ term, start, end }] }) — admin
async function saveTermDates(sql, event) {
  try {
    const { academicYear, terms } = JSON.parse(event.body || '{}');
    if (!/^\d{4}-\d{4}$/.test(academicYear || '') || !Array.isArray(terms)) return json({ error: 'Academic year (e.g. 2026-2027) and terms are required' }, 400);
    const ok = terms.filter(t => t && ['Term 1', 'Term 2', 'Term 3'].includes(t.term) && ISO_DATE.test(t.start || '') && ISO_DATE.test(t.end || ''));
    if (!ok.length) return json({ error: 'Enter the start and end date of at least one term' }, 400);
    for (const t of ok) if (t.end < t.start) return json({ error: `${t.term}: the end date is before the start date` }, 400);
    const sorted = ok.slice().sort((a, b) => a.start.localeCompare(b.start));
    for (let i = 1; i < sorted.length; i++) if (sorted[i].start <= sorted[i - 1].end) return json({ error: `${sorted[i - 1].term} and ${sorted[i].term} overlap` }, 400);
    for (const t of ok) {
      await sql`
        INSERT INTO term_dates (academic_year, term, start_date, end_date) VALUES (${academicYear}, ${t.term}, ${t.start}::date, ${t.end}::date)
        ON CONFLICT (academic_year, term) DO UPDATE SET start_date = EXCLUDED.start_date, end_date = EXCLUDED.end_date`;
    }
    return json({ success: true, message: `Term dates saved for ${academicYear}` });
  } catch (err) {
    console.error('save-term-dates error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// attendance-book (GET ?academicYear&gradeLevel&className&from&to) — admin.
// Like the paper register: every student x every school day in the period (max ~4 months).
async function attendanceBook(sql, event) {
  try {
    const { academicYear, gradeLevel, className, from, to } = event.queryStringParameters || {};
    if (!academicYear || !gradeLevel || !className || !ISO_DATE.test(from || '') || !ISO_DATE.test(to || '')) {
      return json({ error: 'Year, grade, class and the period are required' }, 400);
    }
    const days = Math.round((new Date(to + 'T00:00:00Z') - new Date(from + 'T00:00:00Z')) / 86400000) + 1;
    if (days < 1 || days > 130) return json({ error: 'Choose a period of up to about 4 months (one term)' }, 400);
    const students = await sql`
      SELECT e.student_id, COALESCE(s.full_name, e.full_name) AS full_name, COALESCE(s.status, 'deleted') AS status
      FROM student_enrollments e LEFT JOIN students s ON s.student_id = e.student_id
      WHERE e.academic_year = ${academicYear} AND e.grade_level = ${parseInt(gradeLevel)} AND UPPER(e.class_name) = ${normClass(className)}
      ORDER BY full_name`;
    const marks = await sql`
      SELECT a.student_id, to_char(a.attendance_date, 'YYYY-MM-DD') AS date, a.status
      FROM attendance a
      WHERE a.academic_year = ${academicYear} AND a.attendance_date BETWEEN ${from}::date AND ${to}::date
        AND a.student_id IN (SELECT e.student_id FROM student_enrollments e WHERE e.academic_year = ${academicYear} AND e.grade_level = ${parseInt(gradeLevel)} AND UPPER(e.class_name) = ${normClass(className)})`;
    const holidays = await sql`
      SELECT to_char(holiday_date, 'YYYY-MM-DD') AS date, name FROM school_holidays WHERE holiday_date BETWEEN ${from}::date AND ${to}::date`;
    const changes = await sql`
      SELECT COUNT(*)::int AS n FROM attendance_history h
      WHERE h.attendance_date BETWEEN ${from}::date AND ${to}::date
        AND h.student_id IN (SELECT e.student_id FROM student_enrollments e WHERE e.academic_year = ${academicYear} AND e.grade_level = ${parseInt(gradeLevel)} AND UPPER(e.class_name) = ${normClass(className)})`;
    return json({ success: true, from, to, students, marks, holidays, corrections: changes[0].n });
  } catch (err) {
    console.error('attendance-book error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// get-teachers (GET) — admin
async function getTeachers(sql) {
  try {
    const teachers = await sql`SELECT id, username, full_name, phone, active, to_char(created_at, 'DD/MM/YYYY') AS created FROM teachers ORDER BY full_name`;
    const assignments = await sql`SELECT id, teacher_id, academic_year, grade_level, class_name, subject FROM teacher_assignments ORDER BY academic_year DESC, grade_level, class_name, subject`;
    return json({ success: true, teachers, assignments });
  } catch (err) {
    console.error('get-teachers error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// save-teacher (POST) — admin. Create, edit, reset password, or enable/disable.
async function saveTeacher(sql, event) {
  try {
    const { id, username, fullName, phone, password, active } = JSON.parse(event.body || '{}');

    // Enable / disable only
    if (id && typeof active === 'boolean' && !username) {
      const rows = await sql`UPDATE teachers SET active = ${active} WHERE id = ${parseInt(id)} RETURNING id`;
      if (!rows.length) return json({ success: false, error: 'Teacher not found' }, 404);
      return json({ success: true, message: active ? 'Teacher account enabled' : 'Teacher account disabled' });
    }

    if (!username || !fullName) return json({ error: 'Username and full name are required' }, 400);
    const uname = String(username).trim();
    if (!/^[A-Za-z0-9._-]{3,40}$/.test(uname)) return json({ error: 'Username must be 3-40 letters, numbers, dot, dash or underscore (no spaces)' }, 400);
    if (password && String(password).length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);

    if (id) {
      const rows = await sql`
        UPDATE teachers SET username = ${uname}, full_name = ${String(fullName).trim()}, phone = ${phone || null}
        WHERE id = ${parseInt(id)} RETURNING id
      `;
      if (!rows.length) return json({ success: false, error: 'Teacher not found' }, 404);
      if (password) {
        await sql`UPDATE teachers SET password = ${hashPassword(password)} WHERE id = ${parseInt(id)}`;
        await clearFails(sql, 'teacher:' + uname.toLowerCase());
      }
      return json({ success: true, message: 'Teacher updated' + (password ? ' (password changed)' : '') });
    }

    if (!password) return json({ error: 'A password is required for a new teacher' }, 400);
    await sql`
      INSERT INTO teachers (username, full_name, phone, password)
      VALUES (${uname}, ${String(fullName).trim()}, ${phone || null}, ${hashPassword(password)})
    `;
    return json({ success: true, message: `Teacher ${String(fullName).trim()} created` });
  } catch (err) {
    console.error('save-teacher error:', err);
    if (err.code === '23505') return json({ success: false, error: 'That username is already taken' }, 409);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// teacher-assignment (POST { action: 'add' | 'remove', ... }) — admin
async function teacherAssignment(sql, event) {
  try {
    const { action, id, teacherId, academicYear, gradeLevel, className, subjects } = JSON.parse(event.body || '{}');
    if (action === 'remove') {
      if (!id) return json({ error: 'id is required' }, 400);
      const rows = await sql`DELETE FROM teacher_assignments WHERE id = ${parseInt(id)} RETURNING id`;
      if (!rows.length) return json({ success: false, error: 'Assignment not found' }, 404);
      return json({ success: true, message: 'Assignment removed' });
    }
    if (!teacherId || !academicYear || !gradeLevel || !className || !Array.isArray(subjects) || !subjects.length) {
      return json({ error: 'Teacher, academic year, grade, class and at least one subject are required' }, 400);
    }
    const t = await sql`SELECT id FROM teachers WHERE id = ${parseInt(teacherId)}`;
    if (!t.length) return json({ success: false, error: 'Teacher not found' }, 404);
    const subs = subjects.map(s => String(s).trim()).filter(Boolean);
    const rows = await sql`
      INSERT INTO teacher_assignments (teacher_id, academic_year, grade_level, class_name, subject)
      SELECT ${parseInt(teacherId)}, ${academicYear}, ${parseInt(gradeLevel)}, ${normClass(className)}, sub
      FROM unnest(${subs}::text[]) AS sub
      ON CONFLICT (teacher_id, academic_year, grade_level, class_name, subject) DO NOTHING
      RETURNING id
    `;
    return json({ success: true, message: `Assigned ${rows.length} new subject(s)` + (rows.length < subs.length ? ' (others were already assigned)' : '') });
  } catch (err) {
    console.error('teacher-assignment error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-term-remarks  (GET ?academicYear&term)  — admin
// All saved report remarks for one year + term (for printing many report cards at once).
// ---------------------------------------------------------------------------
async function getTermRemarks(sql, event) {
  try {
    const { academicYear, term } = event.queryStringParameters || {};
    if (!academicYear || !term) return json({ error: 'academicYear and term are required' }, 400);
    const remarks = await sql`
      SELECT student_id, time_absent, times_late, conduct, teacher_remarks,
             teacher_signature, head_remarks, next_term_begins
      FROM report_remarks
      WHERE academic_year = ${academicYear} AND term = ${term}
    `;
    return json({ success: true, remarks });
  } catch (err) {
    console.error('get-term-remarks error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// get-enrollments  (GET)  — admin
// Every student in every academic year (with the grade/class of that year).
// ---------------------------------------------------------------------------
async function getEnrollments(sql) {
  try {
    const enrollments = await sql`
      SELECT e.student_id,
             COALESCE(s.full_name, e.full_name) AS full_name,
             e.academic_year, e.grade_level, e.class_name,
             COALESCE(s.status, 'deleted') AS status
      FROM student_enrollments e
      LEFT JOIN students s ON s.student_id = e.student_id
      ORDER BY e.academic_year DESC, e.grade_level, e.class_name, full_name
    `;
    return json({ success: true, enrollments });
  } catch (err) {
    console.error('get-enrollments error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// student-history  (GET ?studentId)  — admin
// Everything on record for one student, across every year.
// ---------------------------------------------------------------------------
async function studentHistory(sql, event) {
  try {
    const { studentId } = event.queryStringParameters || {};
    if (!studentId) return json({ error: 'studentId is required' }, 400);
    const [studentRows, enrollments, results, payments, remarks] = await Promise.all([
      sql`SELECT student_id, full_name, grade_level, class_name, academic_year, status, archived_at, archive_reason
          FROM students WHERE student_id = ${studentId} LIMIT 1`,
      sql`SELECT academic_year, grade_level, class_name, full_name
          FROM student_enrollments WHERE student_id = ${studentId} ORDER BY academic_year DESC`,
      sql`SELECT subject, score, grade, academic_year, term, grade_level, class_name
          FROM results WHERE student_id = ${studentId} ORDER BY academic_year DESC, term, subject`,
      sql`SELECT id, academic_year, term, amount::float AS amount, method, receipt_no, note,
                 to_char(paid_on, 'YYYY-MM-DD') AS paid_on, grade_level, class_name,
                 student_name, voided, void_reason
          FROM fee_payments WHERE student_id = ${studentId} ORDER BY paid_on DESC, id DESC`,
      sql`SELECT academic_year, term, conduct, teacher_remarks, head_remarks
          FROM report_remarks WHERE student_id = ${studentId}`,
    ]);
    const student = studentRows[0] || null;
    const yearSet = new Set();
    [enrollments, results, payments, remarks].forEach(list =>
      list.forEach(r => { if (r.academic_year) yearSet.add(r.academic_year); })
    );
    if (student && student.academic_year) yearSet.add(student.academic_year);
    const years = [...yearSet].sort().reverse();
    if (!student && !years.length) return json({ success: false, error: 'No records found for this student ID' }, 404);

    const fees = years.length
      ? await sql`SELECT academic_year, term, grade_level, amount::float AS amount
                  FROM fee_structures WHERE academic_year = ANY(${years})`
      : [];
    const fullName = (student && student.full_name)
      || (enrollments[0] && enrollments[0].full_name)
      || (payments[0] && payments[0].student_name)
      || studentId;

    return json({
      success: true,
      student_id: student ? student.student_id : studentId,
      full_name: fullName,
      student, years, enrollments, results, payments, remarks, fees,
    });
  } catch (err) {
    console.error('student-history error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// migrate: creates / patches every table and column. Safe to run any time.
// Runs automatically the first time the API starts after new code is
// uploaded (see ensureSchema), so the setup link is no longer required.
// ---------------------------------------------------------------------------
async function migrate(sql) {
    await sql`
      CREATE TABLE IF NOT EXISTS students (
        id             SERIAL PRIMARY KEY,
        student_id     TEXT UNIQUE NOT NULL,
        full_name      TEXT NOT NULL,
        password_hash  TEXT NOT NULL,
        grade_level    INTEGER,
        class_name     TEXT,
        date_of_birth  DATE,
        gender         TEXT CHECK (gender IN ('Male', 'Female')),
        student_phone  TEXT,
        guardian_name  TEXT,
        guardian_phone TEXT,
        address        TEXT,
        place_of_birth TEXT,
        mother_name    TEXT,
        mother_phone   TEXT,
        father_name    TEXT,
        father_phone   TEXT,
        profile_photo  TEXT,
        upload_blocked BOOLEAN DEFAULT FALSE,
        created_at     TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS upload_blocked BOOLEAN DEFAULT FALSE`;
    await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS academic_year TEXT`;
    await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'`;
    await sql`UPDATE students SET academic_year = '2026-2027' WHERE academic_year IS NULL`;
    await sql`UPDATE students SET status = 'active' WHERE status IS NULL`;

    await sql`
      CREATE TABLE IF NOT EXISTS results (
        id            SERIAL PRIMARY KEY,
        student_id    TEXT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
        subject       TEXT NOT NULL,
        score         INTEGER CHECK (score >= 0 AND score <= 100),
        grade         TEXT,
        academic_year TEXT NOT NULL,
        term          TEXT NOT NULL,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (student_id, subject, academic_year, term)
      )
    `;
    await sql`ALTER TABLE results ADD COLUMN IF NOT EXISTS grade_level INTEGER`;
    await sql`ALTER TABLE results ADD COLUMN IF NOT EXISTS class_name TEXT`;
    await sql`
      UPDATE results r
      SET grade_level = s.grade_level, class_name = s.class_name
      FROM students s
      WHERE r.student_id = s.student_id AND r.grade_level IS NULL
    `;

    await sql`
      CREATE TABLE IF NOT EXISTS admins (
        id         SERIAL PRIMARY KEY,
        username   TEXT UNIQUE NOT NULL,
        password   TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // Only seed an admin if none exist, and only from an env var (no default password).
    const adminCount = await sql`SELECT COUNT(*)::int AS cnt FROM admins`;
    if (adminCount[0].cnt === 0 && process.env.ADMIN_INITIAL_PASSWORD) {
      await sql`INSERT INTO admins (username, password) VALUES ('admin', ${hashPassword(process.env.ADMIN_INITIAL_PASSWORD)})`;
    }

    await sql`CREATE INDEX IF NOT EXISTS idx_results_student_id ON results(student_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_results_grade_class ON results(student_id, academic_year, term)`;

    await sql`
      CREATE TABLE IF NOT EXISTS report_remarks (
        id                SERIAL PRIMARY KEY,
        student_id        TEXT NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
        academic_year     TEXT NOT NULL,
        term              TEXT NOT NULL,
        time_absent       TEXT,
        times_late        TEXT,
        conduct           TEXT,
        teacher_remarks   TEXT,
        teacher_signature TEXT,
        head_remarks      TEXT,
        next_term_begins  TEXT,
        created_at        TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (student_id, academic_year, term)
      )
    `;

    // ---- Records protection: students are archived, never deleted ----
    await sql`
      ALTER TABLE students
        ADD COLUMN IF NOT EXISTS archived_at           TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS archive_reason        TEXT,
        ADD COLUMN IF NOT EXISTS archived_by           TEXT,
        ADD COLUMN IF NOT EXISTS status_before_archive TEXT
    `;
    // Safety net: the database now REFUSES to delete a student who has
    // results or remarks (it used to silently delete them with the student).
    // Each is one statement, so it is applied all-or-nothing.
    await sql`
      ALTER TABLE results
        DROP CONSTRAINT IF EXISTS results_student_id_fkey,
        ADD CONSTRAINT results_student_id_fkey
          FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE RESTRICT
    `;
    await sql`
      ALTER TABLE report_remarks
        DROP CONSTRAINT IF EXISTS report_remarks_student_id_fkey,
        ADD CONSTRAINT report_remarks_student_id_fkey
          FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE RESTRICT
    `;
    // Every overwritten or deleted mark is copied here first.
    await sql`
      CREATE TABLE IF NOT EXISTS results_archive (
        id            SERIAL PRIMARY KEY,
        student_id    TEXT NOT NULL,
        subject       TEXT,
        score         INTEGER,
        grade         TEXT,
        academic_year TEXT,
        term          TEXT,
        grade_level   INTEGER,
        class_name    TEXT,
        action        TEXT NOT NULL,
        action_by     TEXT,
        action_at     TIMESTAMPTZ DEFAULT NOW()
      )
    `;

    // ---- Website content: pictures, slideshow, news (nothing is ever deleted) ----
    await sql`
      CREATE TABLE IF NOT EXISTS media (
        id          SERIAL PRIMARY KEY,
        mime        TEXT NOT NULL,
        data        TEXT NOT NULL,
        size        INTEGER,
        uploaded_by TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS slides (
        id         SERIAL PRIMARY KEY,
        media_id   INTEGER REFERENCES media(id),
        image_path TEXT,
        caption    TEXT,
        sort_order INTEGER NOT NULL DEFAULT 0,
        active     BOOLEAN NOT NULL DEFAULT TRUE,
        created_by TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS news_posts (
        id           SERIAL PRIMARY KEY,
        title        TEXT NOT NULL,
        category     TEXT,
        body         TEXT NOT NULL,
        media_id     INTEGER REFERENCES media(id),
        image_path   TEXT,
        featured     BOOLEAN NOT NULL DEFAULT FALSE,
        status       TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('published', 'hidden')),
        author       TEXT,
        published_at TIMESTAMPTZ,
        created_by   TEXT,
        updated_by   TEXT,
        created_at   TIMESTAMPTZ DEFAULT NOW(),
        updated_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS news_history (
        id         SERIAL PRIMARY KEY,
        post_id    INTEGER NOT NULL REFERENCES news_posts(id),
        title      TEXT,
        category   TEXT,
        body       TEXT,
        media_id   INTEGER,
        image_path TEXT,
        featured   BOOLEAN,
        status     TEXT,
        action     TEXT NOT NULL,
        edited_by  TEXT,
        edited_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_news_status ON news_posts(status, published_at DESC)`;

    // ---- Repeat a grade (held back at next promotion) ----
    await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS repeat_next BOOLEAN DEFAULT FALSE`;

    // ---- Teachers, assignments, attendance ----
    await sql`
      ALTER TABLE results
        ADD COLUMN IF NOT EXISTS entered_by TEXT,
        ADD COLUMN IF NOT EXISTS entered_at TIMESTAMPTZ
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS teachers (
        id         SERIAL PRIMARY KEY,
        username   TEXT UNIQUE NOT NULL,
        full_name  TEXT NOT NULL,
        phone      TEXT,
        password   TEXT NOT NULL,
        active     BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_teachers_username_lower ON teachers (LOWER(username))`;
    await sql`
      CREATE TABLE IF NOT EXISTS teacher_assignments (
        id            SERIAL PRIMARY KEY,
        teacher_id    INTEGER NOT NULL REFERENCES teachers(id),
        academic_year TEXT NOT NULL,
        grade_level   INTEGER NOT NULL,
        class_name    TEXT NOT NULL,
        subject       TEXT NOT NULL,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (teacher_id, academic_year, grade_level, class_name, subject)
      )
    `;
    // No foreign key to students on purpose: attendance history is never lost.
    await sql`
      CREATE TABLE IF NOT EXISTS attendance (
        id              SERIAL PRIMARY KEY,
        student_id      TEXT NOT NULL,
        attendance_date DATE NOT NULL,
        academic_year   TEXT NOT NULL,
        grade_level     INTEGER,
        class_name      TEXT,
        status          TEXT NOT NULL CHECK (status IN ('present', 'absent', 'late', 'excused')),
        marked_by       TEXT,
        marked_at       TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (student_id, attendance_date)
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_attendance_class ON attendance(academic_year, grade_level, class_name, attendance_date)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance(student_id, academic_year)`;

    // ---- Activity log (security): who did what, when. Stored forever, owner-only. ----
    await sql`
      CREATE TABLE IF NOT EXISTS activity_log (
        id          BIGSERIAL PRIMARY KEY,
        at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        actor_role  TEXT, actor_name TEXT, action TEXT NOT NULL, category TEXT,
        detail TEXT, target TEXT, method TEXT, route TEXT, ok BOOLEAN, ip TEXT, device TEXT
      )
    `;
    await sql`ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS location TEXT`;
    await sql`CREATE INDEX IF NOT EXISTS idx_activity_at ON activity_log(at DESC)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_log(actor_name, at DESC)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_activity_cat ON activity_log(category, at DESC)`;
    await sql`
      CREATE TABLE IF NOT EXISTS owners (
        id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;

    // ---- Attendance history: a corrected mark keeps its old value here (nothing is ever lost) ----
    await sql`
      CREATE TABLE IF NOT EXISTS attendance_history (
        id              SERIAL PRIMARY KEY,
        student_id      TEXT NOT NULL,
        attendance_date DATE NOT NULL,
        old_status      TEXT,
        new_status      TEXT,
        old_marked_by   TEXT,
        changed_by      TEXT,
        changed_at      TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // ---- Term dates (per academic year) — used for "Term 1 / 2 / 3" filters ----
    await sql`
      CREATE TABLE IF NOT EXISTS term_dates (
        academic_year TEXT NOT NULL,
        term          TEXT NOT NULL,
        start_date    DATE NOT NULL,
        end_date      DATE NOT NULL,
        PRIMARY KEY (academic_year, term)
      )
    `;

    // ---- Public holidays: no register on these days, never counted in attendance ----
    await sql`
      CREATE TABLE IF NOT EXISTS school_holidays (
        id           SERIAL PRIMARY KEY,
        holiday_date DATE UNIQUE NOT NULL,
        name         TEXT NOT NULL,
        created_by   TEXT,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `;

    // ---- Teacher access links (only a hash of each key is stored) ----
    await sql`
      CREATE TABLE IF NOT EXISTS staff_links (
        id           SERIAL PRIMARY KEY,
        teacher_id   INTEGER NOT NULL REFERENCES teachers(id),
        key_hash     TEXT UNIQUE NOT NULL,
        expires_at   TIMESTAMPTZ NOT NULL,
        revoked      BOOLEAN NOT NULL DEFAULT FALSE,
        revoked_at   TIMESTAMPTZ,
        revoked_by   TEXT,
        last_used_at TIMESTAMPTZ,
        created_by   TEXT,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `;


    // ---- Security: server-side login lockout ----
    await sql`
      CREATE TABLE IF NOT EXISTS login_attempts (
        key          TEXT PRIMARY KEY,
        fails        INTEGER NOT NULL DEFAULT 0,
        locked_until TIMESTAMPTZ
      )
    `;

    // ---- Enrollment history: grade/class per student per academic year ----
    // No foreign key on purpose: history survives if a student is deleted.
    await sql`
      CREATE TABLE IF NOT EXISTS student_enrollments (
        id            SERIAL PRIMARY KEY,
        student_id    TEXT NOT NULL,
        academic_year TEXT NOT NULL,
        grade_level   INTEGER NOT NULL,
        class_name    TEXT,
        full_name     TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (student_id, academic_year)
      )
    `;
    // Backfill past years from the grade snapshotted on results...
    await sql`
      INSERT INTO student_enrollments (student_id, academic_year, grade_level, class_name, full_name)
      SELECT DISTINCT ON (r.student_id, r.academic_year)
             r.student_id, r.academic_year, r.grade_level, r.class_name, s.full_name
      FROM results r
      JOIN students s ON s.student_id = r.student_id
      WHERE r.grade_level IS NOT NULL
      ORDER BY r.student_id, r.academic_year, r.created_at DESC
      ON CONFLICT (student_id, academic_year) DO NOTHING
    `;
    // ...and the current year from the students table.
    await sql`
      INSERT INTO student_enrollments (student_id, academic_year, grade_level, class_name, full_name)
      SELECT student_id, academic_year, grade_level, class_name, full_name
      FROM students
      WHERE academic_year IS NOT NULL AND grade_level IS NOT NULL
      ON CONFLICT (student_id, academic_year) DO UPDATE SET
        grade_level = EXCLUDED.grade_level,
        class_name  = EXCLUDED.class_name,
        full_name   = EXCLUDED.full_name
    `;

    // ---- Finance ----
    await sql`
      CREATE TABLE IF NOT EXISTS fee_structures (
        id            SERIAL PRIMARY KEY,
        academic_year TEXT NOT NULL,
        term          TEXT NOT NULL,
        grade_level   INTEGER NOT NULL,
        amount        NUMERIC(12,2) NOT NULL DEFAULT 0,
        description   TEXT,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (academic_year, term, grade_level)
      )
    `;
    // No foreign key on purpose: payments survive if a student is deleted.
    await sql`
      CREATE TABLE IF NOT EXISTS fee_payments (
        id            SERIAL PRIMARY KEY,
        student_id    TEXT NOT NULL,
        academic_year TEXT NOT NULL,
        term          TEXT NOT NULL,
        amount        NUMERIC(12,2) NOT NULL CHECK (amount > 0),
        method        TEXT,
        receipt_no    TEXT UNIQUE,
        note          TEXT,
        paid_on       DATE DEFAULT CURRENT_DATE,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // If fee_payments was created by the earlier version (with ON DELETE CASCADE), remove that link.
    await sql`ALTER TABLE fee_payments DROP CONSTRAINT IF EXISTS fee_payments_student_id_fkey`;
    await sql`

      ALTER TABLE fee_payments
        ADD COLUMN IF NOT EXISTS student_name TEXT,
        ADD COLUMN IF NOT EXISTS grade_level  INTEGER,
        ADD COLUMN IF NOT EXISTS class_name   TEXT,
        ADD COLUMN IF NOT EXISTS recorded_by  TEXT,
        ADD COLUMN IF NOT EXISTS voided       BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS void_reason  TEXT,
        ADD COLUMN IF NOT EXISTS voided_at    TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS voided_by    TEXT
    `;

    // ---- Fee items (Tuition, Registration, School Development, ...) ----
    // Each item is paid either every term or once a year (admin chooses).
    await sql`
      CREATE TABLE IF NOT EXISTS fee_items (
        id          SERIAL PRIMARY KEY,
        name        TEXT UNIQUE NOT NULL,
        frequency   TEXT NOT NULL DEFAULT 'term' CHECK (frequency IN ('term', 'year')),
        active      BOOLEAN NOT NULL DEFAULT TRUE,
        is_default  BOOLEAN NOT NULL DEFAULT FALSE,
        sort_order  INTEGER NOT NULL DEFAULT 0,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // First time only: create the school's three items. Tuition is the default item,
    // so fee amounts and payments recorded before fee items existed count as Tuition.
    await sql`
      INSERT INTO fee_items (name, frequency, is_default, sort_order)
      SELECT v.name, v.frequency, v.is_default, v.sort_order
      FROM (VALUES ('Tuition', 'term', TRUE, 1), ('Registration', 'year', FALSE, 2), ('School Development', 'year', FALSE, 3))
           AS v(name, frequency, is_default, sort_order)
      WHERE NOT EXISTS (SELECT 1 FROM fee_items)
    `;
    await sql`ALTER TABLE fee_structures ADD COLUMN IF NOT EXISTS fee_item_id INTEGER`;
    await sql`UPDATE fee_structures SET fee_item_id = (SELECT id FROM fee_items WHERE is_default ORDER BY id LIMIT 1) WHERE fee_item_id IS NULL`;
    await sql`ALTER TABLE fee_structures DROP CONSTRAINT IF EXISTS fee_structures_academic_year_term_grade_level_key`;
    await sql`CREATE UNIQUE INDEX IF NOT EXISTS uq_fee_structures_item ON fee_structures (academic_year, term, grade_level, fee_item_id)`;
    // Payments keep their original rows untouched; older payments (no item) are read as the default item.
    await sql`ALTER TABLE fee_payments ADD COLUMN IF NOT EXISTS fee_item_id INTEGER, ADD COLUMN IF NOT EXISTS fee_item_name TEXT`;
    await sql`
      UPDATE fee_payments p SET student_name = s.full_name
      FROM students s
      WHERE s.student_id = p.student_id AND p.student_name IS NULL
    `;
    await sql`
      UPDATE fee_payments p SET grade_level = e.grade_level, class_name = e.class_name
      FROM student_enrollments e
      WHERE e.student_id = p.student_id AND e.academic_year = p.academic_year AND p.grade_level IS NULL
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_fee_payments_student ON fee_payments(student_id, academic_year, term)`;

}

let schemaReady = false;
async function ensureSchema(sql) {
  if (schemaReady) return;
  const r = await sql`
    SELECT
      to_regclass('public.students') IS NOT NULL
      AND to_regclass('public.student_enrollments') IS NOT NULL
      AND to_regclass('public.login_attempts') IS NOT NULL
      AND to_regclass('public.results_archive') IS NOT NULL
      AND to_regclass('public.teachers') IS NOT NULL
      AND to_regclass('public.attendance') IS NOT NULL
      AND to_regclass('public.fee_payments') IS NOT NULL
      AND to_regclass('public.media') IS NOT NULL
      AND to_regclass('public.slides') IS NOT NULL
      AND to_regclass('public.news_history') IS NOT NULL
      AND to_regclass('public.staff_links') IS NOT NULL
      AND to_regclass('public.fee_items') IS NOT NULL
      AND to_regclass('public.school_holidays') IS NOT NULL
      AND to_regclass('public.attendance_history') IS NOT NULL
      AND to_regclass('public.term_dates') IS NOT NULL
      AND to_regclass('public.activity_log') IS NOT NULL
      AND to_regclass('public.owners') IS NOT NULL
      AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'students' AND column_name = 'repeat_next')
      AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'results' AND column_name = 'entered_by')
      AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'fee_payments' AND column_name = 'voided')
      AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'activity_log' AND column_name = 'location')
      AS ok
  `;
  if (!r[0].ok) {
    console.log('Database is missing new tables/columns — updating it automatically...');
    await migrate(sql);
  }
  schemaReady = true;
}

// ---------------------------------------------------------------------------
// init-db  (GET ?secret=)  — needs INIT_SECRET env var.
// Creates/patches all tables and migrates old data. Safe to re-run any time.
// ---------------------------------------------------------------------------
async function initDb(sql, event) {
  const secret = event.queryStringParameters?.secret;
  if (!process.env.INIT_SECRET || secret !== process.env.INIT_SECRET) {
    return json({ error: 'Forbidden' }, 403);
  }
  try {
    await migrate(sql);

    // ---- Upgrade plain-text passwords to hashes ----
    const plainAdmins = await sql`SELECT id, password FROM admins WHERE password NOT LIKE 'scrypt$%'`;
    for (const a of plainAdmins) {
      await sql`UPDATE admins SET password = ${hashPassword(a.password)} WHERE id = ${a.id}`;
    }
    // Students in batches of 60 so this stays under Netlify's 10s limit.
    const plainStudents = await sql`SELECT id, password_hash FROM students WHERE password_hash NOT LIKE 'scrypt$%' LIMIT 60`;
    for (const s of plainStudents) {
      await sql`UPDATE students SET password_hash = ${hashPassword(s.password_hash)} WHERE id = ${s.id}`;
    }
    const left = await sql`SELECT COUNT(*)::int AS cnt FROM students WHERE password_hash NOT LIKE 'scrypt$%'`;
    const remaining = left[0].cnt;

    return json({
      success: true,
      message: remaining > 0
        ? `Database ready! ${remaining} student password(s) still need hashing — open this link again until this says 0.`
        : 'Database ready! All passwords are hashed.',
      remainingPlainPasswords: remaining,
    });
  } catch (err) {
    console.error('init-db error:', err);
    return json({ success: false, error: err.message }, 500);
  }
}

// ---------------------------------------------------------------------------
// Route table + dispatcher
// auth: 'public' = no login | 'user' = student (own data) or admin |
//       'staff' = admin or teacher (teacher limited to assigned classes) | 'admin'
// ---------------------------------------------------------------------------
const ROUTES = {
  'admin-login':           { auth: 'public', POST: adminLogin },
  'owner-login':           { auth: 'public', POST: ownerLogin },
  'owner-setup':           { auth: 'public', GET: ownerSetup },
  'activity-log':          { auth: 'owner',  GET: getActivityLog },
  'activity-summary':      { auth: 'owner',  GET: getActivitySummary },
  'admin-view':            { auth: 'admin',  POST: adminView },
  'sds-feed':              { auth: 'public', GET: sdsFeed },
  'sds-admin':             { auth: 'public', POST: sdsAdmin },
  'student-login':         { auth: 'public', POST: studentLogin },
  'init-db':               { auth: 'public', GET: initDb },

  'student-me':            { auth: 'user', GET: studentMe },
  'get-results':           { auth: 'user', GET: getResults },
  'get-class-stats':       { auth: 'user', GET: getClassStats },
  'get-remarks':           { auth: 'user', GET: getRemarks },
  'upload-photo':          { auth: 'user', POST: uploadPhoto },

  'change-admin-password': { auth: 'admin', POST: changeAdminPassword },
  'get-all-students':      { auth: 'admin', GET: getAllStudents },
  'get-all-results':       { auth: 'admin', GET: getAllResults },
  'add-marks':             { auth: 'admin', POST: addMarks },
  'add-student':           { auth: 'admin', POST: addStudent },
  'update-student':        { auth: 'admin', PUT: updateStudent },
  'promote-students':      { auth: 'admin', POST: promoteStudents },
  'archive-student':       { auth: 'admin', POST: archiveStudent },
  'set-repeat':            { auth: 'admin', POST: setRepeat },
  'image':                 { auth: 'public', GET: getImage },
  'site-content':          { auth: 'public', GET: siteContent },
  'upload-image':          { auth: 'admin', POST: uploadImage },
  'admin-slides':          { auth: 'admin', GET: adminSlides },
  'save-slide':            { auth: 'admin', POST: saveSlide },
  'admin-news':            { auth: 'admin', GET: adminNews },
  'save-news':             { auth: 'admin', POST: saveNews },
  'news-status':           { auth: 'admin', POST: newsStatus },
  'news-history':          { auth: 'admin', GET: newsHistory },
  'demote-student':        { auth: 'admin', POST: demoteStudent },
  'get-enrollments':       { auth: 'admin', GET: getEnrollments },
  'student-history':       { auth: 'admin', GET: studentHistory },
  'get-term-remarks':      { auth: 'admin', GET: getTermRemarks },

  'teacher-login':         { auth: 'public', POST: teacherLogin },
  'teacher-me':            { auth: 'staff', GET: teacherMe },
  'get-class-scores':      { auth: 'staff', GET: getClassScores },
  'save-class-scores':     { auth: 'staff', POST: saveClassScores },
  'get-attendance':        { auth: 'staff', GET: getAttendance },
  'save-attendance':       { auth: 'staff', POST: saveAttendance },
  'attendance-report':     { auth: 'staff', GET: attendanceReport },
  'get-holidays':          { auth: 'staff', GET: getHolidays },
  'save-holiday':          { auth: 'admin', POST: saveHoliday },
  'delete-holiday':        { auth: 'admin', POST: deleteHoliday },
  'student-attendance':    { auth: 'admin', GET: studentAttendance },
  'school-attendance':     { auth: 'admin', GET: schoolAttendance },
  'attendance-book':       { auth: 'admin', GET: attendanceBook },
  'get-term-dates':        { auth: 'staff', GET: getTermDates },
  'save-term-dates':       { auth: 'admin', POST: saveTermDates },
  'get-teachers':          { auth: 'admin', GET: getTeachers },
  'save-teacher':          { auth: 'admin', POST: saveTeacher },
  'teacher-assignment':    { auth: 'admin', POST: teacherAssignment },
  'staff-links':           { auth: 'admin', GET: staffLinks },
  'create-staff-link':     { auth: 'admin', POST: createStaffLink },
  'revoke-staff-link':     { auth: 'admin', POST: revokeStaffLink },
  'delete-staff-link':     { auth: 'admin', POST: deleteStaffLink },
  'delete-teacher':        { auth: 'admin', POST: deleteTeacher },
  'delete-results':        { auth: 'admin', DELETE: deleteResults },
  'reset-password':        { auth: 'admin', PUT: resetPassword },
  'block-upload':          { auth: 'admin', POST: blockUpload },
  'save-remarks':          { auth: 'admin', POST: saveRemarks },
  'get-student-photo':     { auth: 'admin', GET: getStudentPhoto },
  'admin-upload-photo':    { auth: 'admin', POST: adminUploadPhoto },
  'get-fee-items':         { auth: 'admin', GET: getFeeItems },
  'save-fee-item':         { auth: 'admin', POST: saveFeeItem },
  'get-fee-structures':    { auth: 'admin', GET: getFeeStructures },
  'save-fee-structure':    { auth: 'admin', POST: saveFeeStructure },
  'record-payment':        { auth: 'admin', POST: recordPayment },
  'get-payments':          { auth: 'admin', GET: getPayments },
  'void-payment':          { auth: 'admin', POST: voidPayment },
  'get-fee-summary':       { auth: 'admin', GET: getFeeSummary },
};

export async function handler(event) {
  if (event.httpMethod === 'OPTIONS') return preflight();

  const route = getRoute(event);
  const entry = ROUTES[route];
  if (!entry) {
    return json({ error: `Unknown API route: "${route}"` }, 404);
  }
  const fn = entry[event.httpMethod];
  if (!fn) {
    return json({ error: 'Method not allowed' }, 405);
  }

  let auth = null;
  if (entry.auth !== 'public') {
    try {
      auth = getAuth(event);
    } catch (err) {
      console.error('auth config error:', err);
      return json({ success: false, error: 'Server misconfigured (AUTH_SECRET missing)' }, 500);
    }
    if (!auth) {
      return json({ success: false, error: 'Not logged in or session expired' }, 401);
    }
    if (entry.auth === 'admin' && auth.role !== 'admin') {
      return json({ success: false, error: 'Admins only' }, 403);
    }
    if (entry.auth === 'owner' && auth.role !== 'owner') {
      return json({ success: false, error: 'Owner only' }, 403);
    }
    if (entry.auth === 'staff' && auth.role !== 'admin' && auth.role !== 'teacher') {
      return json({ success: false, error: 'Staff only' }, 403);
    }
  }

  let sql;
  try {
    sql = getDb();
  } catch (err) {
    console.error('db init error:', err);
    return json({ success: false, error: 'Server misconfigured (DATABASE_URL missing)' }, 500);
  }

  // Keep the database up to date with the code automatically.
  if (route !== 'init-db' && route !== 'image') {
    try { await ensureSchema(sql); } catch (err) { console.error('auto-migrate error:', err); }
  }

  // Teachers: their personal access link must still be valid on every request.
  if (auth && auth.role === 'teacher') {
    const ok = auth.lid ? await sql`SELECT 1 FROM staff_links WHERE id = ${auth.lid} AND revoked = FALSE AND expires_at > NOW()` : [];
    if (!ok.length) {
      return json({ success: false, linkExpired: true, error: 'Your access link has expired or was cancelled. Ask the admin for a new link.' }, 401);
    }
  }

  const result = await fn(sql, event, auth);

  // ---- Activity log: logins, failed logins, and every change an admin/teacher makes ----
  try {
    let ok = true; try { ok = JSON.parse((result && result.body) || '{}').success !== false; } catch (e) {}
    if (route === 'admin-login' || route === 'owner-login' || route === 'teacher-login' || route === 'student-login') {
      let who = {}; try { who = JSON.parse(event.body || '{}'); } catch (e) {}
      const name = (route === 'student-login' ? 'student:' : route === 'teacher-login' ? 'teacher:' : route === 'owner-login' ? 'owner:' : 'admin:') + (who.adminId || who.username || who.studentId || '?');
      await logActivity(sql, event, { role: route.split('-')[0], name, action: route, ok, detail: ok ? null : 'Failed login attempt' });
    } else if (auth && (auth.role === 'admin' || auth.role === 'teacher') && event.httpMethod !== 'GET' && ACTION_INFO[route]) {
      let tgt = null; try { const b = JSON.parse(event.body || '{}'); tgt = b.studentId || b.id || null; } catch (e) {}
      await logActivity(sql, event, { role: auth.role, name: actorName(auth), action: route, ok, detail: logDetailFor(route, event), target: tgt });
    }
  } catch (err) { console.error('activity-log hook failed:', err.message); }

  return result;
}
