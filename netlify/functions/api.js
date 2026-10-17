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
        place_of_birth, mother_name, mother_phone, father_name, father_phone
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

    // 1. Graduate students who are ALREADY grade 9.
    const graduated = await sql`
      UPDATE students
      SET status = 'graduated'
      WHERE status = 'active' AND grade_level = 9
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
      WHERE status = 'active' AND grade_level IN (7, 8)
      RETURNING student_id, grade_level, class_name
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
      message: `Promoted ${promoted.length} student(s) for ${toYear}. ${graduated.length} Grade 9 student(s) marked as graduated.`,
      promotedCount: promoted.length,
      graduatedCount: graduated.length,
    });
  } catch (err) {
    console.error('promote-students error:', err);
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
async function getFeeStructures(sql, event) {
  try {
    const { academicYear } = event.queryStringParameters || {};
    const fees = academicYear
      ? await sql`SELECT id, academic_year, term, grade_level, amount::float AS amount, description
                  FROM fee_structures WHERE academic_year = ${academicYear}
                  ORDER BY grade_level, term`
      : await sql`SELECT id, academic_year, term, grade_level, amount::float AS amount, description
                  FROM fee_structures ORDER BY academic_year DESC, grade_level, term`;
    return json({ success: true, fees });
  } catch (err) {
    console.error('get-fee-structures error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

async function saveFeeStructure(sql, event) {
  try {
    const { academicYear, term, gradeLevel, amount, description } = JSON.parse(event.body || '{}');
    if (!academicYear || !term || !gradeLevel) return json({ error: 'academicYear, term and gradeLevel are required' }, 400);
    const amt = Number(amount);
    if (isNaN(amt) || amt < 0) return json({ error: 'Amount must be 0 or more' }, 400);
    await sql`
      INSERT INTO fee_structures (academic_year, term, grade_level, amount, description)
      VALUES (${academicYear}, ${term}, ${parseInt(gradeLevel)}, ${amt}, ${description || null})
      ON CONFLICT (academic_year, term, grade_level)
      DO UPDATE SET amount = EXCLUDED.amount, description = EXCLUDED.description
    `;
    return json({ success: true, message: 'Fee saved' });
  } catch (err) {
    console.error('save-fee-structure error:', err);
    return json({ success: false, error: 'Server error: ' + err.message }, 500);
  }
}

// record-payment: the grade/class/name used is the student's enrollment for
// THAT academic year, snapshotted onto the payment row.
async function recordPayment(sql, event, auth) {
  try {
    const { studentId, academicYear, term, amount, method, paidOn, note } = JSON.parse(event.body || '{}');
    if (!studentId || !academicYear || !term) return json({ error: 'studentId, academicYear and term are required' }, 400);
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
        academic_year, term, amount, method, receipt_no, note, paid_on, recorded_by
      ) VALUES (
        ${studentId}, ${stu[0].full_name}, ${enr[0].grade_level}, ${enr[0].class_name},
        ${academicYear}, ${term}, ${amt}, ${method || null}, ${receiptNo}, ${note || null},
        COALESCE(${paidOn || null}::date, CURRENT_DATE), ${auth.sub}
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
    const { studentId, academicYear, term } = event.queryStringParameters || {};
    const params = [], conditions = [];
    if (studentId) { params.push(studentId); conditions.push(`p.student_id = $${params.length}`); }
    if (academicYear) { params.push(academicYear); conditions.push(`p.academic_year = $${params.length}`); }
    if (term) { params.push(term); conditions.push(`p.term = $${params.length}`); }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const payments = await sql(`
      SELECT p.id, p.student_id,
             COALESCE(s.full_name, p.student_name) AS full_name,
             p.grade_level, p.class_name,
             p.academic_year, p.term, p.amount::float AS amount, p.method,
             p.receipt_no, p.note, to_char(p.paid_on, 'YYYY-MM-DD') AS paid_on,
             p.recorded_by, p.voided, p.void_reason, p.voided_by
      FROM fee_payments p
      LEFT JOIN students s ON s.student_id = p.student_id
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
    const { academicYear, term, gradeLevel, className, studentId } = event.queryStringParameters || {};
    if (!academicYear || !term) return json({ error: 'academicYear and term are required' }, 400);
    const params = [academicYear, term];
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
      LEFT JOIN fee_structures f
        ON f.grade_level = e.grade_level AND f.academic_year = e.academic_year AND f.term = $2
      LEFT JOIN (
        SELECT student_id, SUM(amount) AS paid
        FROM fee_payments
        WHERE academic_year = $1 AND term = $2 AND voided = FALSE
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
function actorName(auth) { return (auth.role === 'teacher' ? 'teacher:' : 'admin:') + auth.sub; }

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
    const { username, password } = JSON.parse(event.body || '{}');
    if (!username || !password) return json({ error: 'Username and password are required' }, 400);
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
    const token = signToken({ role: 'teacher', sub: t.username, tid: t.id, exp: Date.now() + TEACHER_TOKEN_HOURS * 3600 * 1000 });
    return json({ success: true, token, teacher: { id: t.id, username: t.username, full_name: t.full_name } });
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
    return json({ success: true, teacher: t[0], assignments });
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
    return json({ success: true, date, today: todayISO(), students });
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
// init-db  (GET ?secret=)  — needs INIT_SECRET env var.
// Creates/patches all tables and migrates old data. Safe to re-run any time.
// ---------------------------------------------------------------------------
async function initDb(sql, event) {
  const secret = event.queryStringParameters?.secret;
  if (!process.env.INIT_SECRET || secret !== process.env.INIT_SECRET) {
    return json({ error: 'Forbidden' }, 403);
  }
  try {
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
  'get-teachers':          { auth: 'admin', GET: getTeachers },
  'save-teacher':          { auth: 'admin', POST: saveTeacher },
  'teacher-assignment':    { auth: 'admin', POST: teacherAssignment },
  'delete-results':        { auth: 'admin', DELETE: deleteResults },
  'reset-password':        { auth: 'admin', PUT: resetPassword },
  'block-upload':          { auth: 'admin', POST: blockUpload },
  'save-remarks':          { auth: 'admin', POST: saveRemarks },
  'get-student-photo':     { auth: 'admin', GET: getStudentPhoto },
  'admin-upload-photo':    { auth: 'admin', POST: adminUploadPhoto },
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

  return fn(sql, event, auth);
}
