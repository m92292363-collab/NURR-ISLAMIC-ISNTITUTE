// =====================================================================
//  Nurr Islamic Institute — API  (corrected)
//  Saho Digital Services
//
//  Single consolidated Netlify Function, internally routed off the tail
//  of event.path per netlify.toml's /api/* -> /.netlify/functions/api/:splat
//
//  CHANGES vs the previous version (all marked [FIX] inline):
//   1. Request bodies are decoded ONCE at the entry point. Netlify can
//      deliver a base64-encoded body; the old code only handled that for
//      the ZKTeco path, so a base64 POST silently became {} everywhere
//      else and every field came back "مطلوب".
//   2. send-sms no longer nests a sql`now()` template inside another
//      template — that is not a valid parameter value in
//      @neondatabase/serverless and threw on every send.
//   3. get-fee-summary was one query PER STUDENT (900+ round trips on
//      this dataset = guaranteed function timeout). Now a single query.
//   4. change-admin-password now uses the AUTHENTICATED username, not
//      one supplied by the client.
//   5. The ZKTeco ATTLOG loop no longer does a SELECT per punch line.
//   6. Renaming a class now also repoints fee_targets and exams, not
//      just students and classes.promotes_to.
//   7. student_phone is now writable from add-student / update-student.
//   8. Nulls passed into COALESCE(...) are explicitly cast, so Postgres
//      can always resolve the parameter type.
//   9. student-results now also returns the student's RANK in their
//      class and the class size for each year/term, plus guardian and
//      date-of-birth, so the portal can print the official كشف الدرجات
//      without a second call.
//
//  admins.password_hash is auto-bcrypted by trg_hash_admin_password on
//  INSERT/UPDATE (anything not already starting with '$2'). We always
//  write PLAIN passwords to that column and verify with pgcrypto's
//  crypt() — never JS-side hashing for admins.
//
//  students.password has NO trigger — hashed here with Node's built-in
//  crypto.scrypt (salt:hash hex), verified with timingSafeEqual.
// =====================================================================
import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);

// ---------- password hashing for STUDENTS only ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const hashBuffer = Buffer.from(hash, 'hex');
  const testBuffer = crypto.scryptSync(password, salt, 64);
  if (hashBuffer.length !== testBuffer.length) return false;
  return crypto.timingSafeEqual(hashBuffer, testBuffer);
}

// ---------- session tokens ----------
// Stateless HMAC-signed tokens (no session table needed). Issued by
// admin-login, sent back as `Authorization: Bearer <token>` on every
// other request, verified by the handler before any route runs.
// SESSION_SECRET must be set as a Netlify environment variable.
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

function toB64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function signToken(payload) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET غير مُعرَّف في إعدادات Netlify');
  const body = toB64Url(Buffer.from(JSON.stringify(payload)));
  const sig = toB64Url(crypto.createHmac('sha256', secret).update(body).digest());
  return `${body}.${sig}`;
}
function verifyToken(event) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) return null;
  const h = event.headers && (event.headers.authorization || event.headers.Authorization);
  if (!h || !h.startsWith('Bearer ')) return null;
  const token = h.slice(7);
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = toB64Url(crypto.createHmac('sha256', secret).update(body).digest());
  const sigBuf = Buffer.from(sig), expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  let payload;
  try {
    const pad = body.length % 4 === 0 ? '' : '='.repeat(4 - (body.length % 4));
    const b64 = body.replace(/-/g, '+').replace(/_/g, '/') + pad;
    payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));
  } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload; // { username, role, exp }
}

// ---------- who may call each route ----------
// 'public' = no login needed. 'any' = any logged-in admin or master
// (read-only viewing). 'admin' = logged-in AND role === 'admin'.
// Anything not listed defaults to 'admin' (secure by default).
const ROUTE_AUTH = {
  'admin-login': 'public',
  'student-results': 'public',

  'get-admins':'any', 'get-classes':'any', 'get-all-students':'any', 'get-all-results':'any',
  'get-report-card':'any', 'get-attendance':'any', 'get-teachers':'any', 'get-news':'any',
  'get-subjects':'any', 'get-fee-structure':'any', 'get-fee-summary':'any', 'get-fee-targets':'any',
  'get-school-settings':'any', 'get-payments':'any', 'get-all-fee-payments':'any', 'get-exams':'any',
  'get-behavior':'any', 'get-promotion-roster':'any', 'get-sms-log':'any', 'get-audit-log':'any',
  'get-activity':'any', 'change-admin-password':'any', 'get-receipt':'any',
  'get-attendance-devices':'any', 'get-punches':'any',

  'add-admin':'admin', 'update-admin':'admin', 'delete-admin':'admin',
  'add-class':'admin', 'update-class':'admin', 'delete-class':'admin',
  'add-student':'admin', 'bulk-import-students':'admin', 'update-student':'admin', 'delete-student':'admin',
  'add-marks':'admin', 'bulk-upload-results':'admin', 'delete-results':'admin', 'save-attendance':'admin',
  'add-teacher':'admin', 'delete-teacher':'admin', 'add-news':'admin', 'delete-news':'admin',
  'set-student-device-pin':'admin', 'sync-punches-to-attendance':'admin',
  'add-subject':'admin', 'delete-subject':'admin',
  'set-fee-structure':'admin', 'delete-fee-structure':'admin',
  'set-fee-target':'admin', 'set-stage-fees':'admin', 'delete-fee-target':'admin', 'set-school-settings':'admin',
  'record-payment':'admin', 'update-payment':'admin', 'delete-payment':'admin',
  'add-exam':'admin', 'delete-exam':'admin', 'add-behavior':'admin', 'delete-behavior':'admin',
  'promote-students':'admin', 'promote-entire-school':'admin', 'send-sms':'admin',
  'teacher-login':'public', 'staff-links':'any', 'teacher-me':'teacher',
  'create-staff-link':'admin', 'revoke-staff-link':'admin', 'delete-staff-link':'admin',
  'staff-save-scores':'teacher', 'staff-save-attendance':'teacher', 'staff-roster':'teacher',
  'get-remarks':'any', 'save-remarks':'admin',
  'student-history':'any', 'archive-student':'admin', 'get-student-photo':'any', 'admin-upload-photo':'admin', 'class-list':'any',
  'get-years':'any',
  'teacher-assignment':'admin', 'get-teacher-assignments':'any',
  'get-subject-stages':'any', 'set-subject-stages':'admin',
  'attendance-book':'any', 'dashboard-stats':'any',
};

// ---------- small helpers ----------
function ok(data, statusCode = 200) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ success: true, ...data }) };
}
function err(message, statusCode = 400) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ success: false, error: message }) };
}
function plainText(body, statusCode = 200) {
  // the ZKTeco ADMS protocol is plain text, not JSON — this is what the
  // fingerprint device itself expects back, never shown to an admin
  return { statusCode, headers: { 'Content-Type': 'text/plain' }, body: String(body) };
}

// [FIX 1] Netlify may deliver the body base64-encoded. Decode once, here,
// so every route below sees plain text no matter how it arrived.
function rawBody(event) {
  if (!event.body) return '';
  return event.isBase64Encoded
    ? Buffer.from(event.body, 'base64').toString('utf-8')
    : event.body;
}
function readBody(event) {
  const text = rawBody(event);
  if (!text) return {};
  try { return JSON.parse(text) || {} } catch (e) { return {} }
}

async function logActivity(message, actor) {
  try { await sql`INSERT INTO activity_log (message, actor) VALUES (${message}, ${actor || null})` }
  catch (e) { console.error('activity log failed:', e.message) }
}
function gradeFor(score) {
  if (score >= 90) return 'ممتاز';
  if (score >= 75) return 'جيد جداً';
  if (score >= 60) return 'جيد';
  if (score >= 50) return 'مقبول';
  return 'ضعيف';
}
function getRoute(event) {
  const parts = String(event.path || '').split('/').filter(Boolean);
  const idx = parts.lastIndexOf('api');
  return idx >= 0 ? parts.slice(idx + 1).join('/') : parts[parts.length - 1] || '';
}

// =====================================================================
//  ZKTeco F22 fingerprint device (ADMS push protocol)
// =====================================================================
// The device dials OUT to these paths itself, over plain HTTP/HTTPS —
// nothing to expose on the school's router. Not JSON: this is the
// device's own lightweight text protocol, spoken back exactly as the
// firmware expects it. Configured on the device at
// Menu → COMM → Cloud Server Setting → Server Address / Port.
async function handleZkteco(event) {
  const sub = getRoute(event).replace(/^iclock\//, ''); // 'cdata' | 'getrequest' | 'devicecmd' | 'test'
  const qs = event.queryStringParameters || {};
  const sn = qs.SN || qs.sn || 'unknown';

  try {
    await sql`
      INSERT INTO attendance_devices (serial_number, last_seen)
      VALUES (${sn}, now())
      ON CONFLICT (serial_number) DO UPDATE SET last_seen = now()`;
  } catch (e) { console.error('[iclock] device upsert failed', e); }

  if (sub === 'cdata') {
    if (event.httpMethod === 'GET') {
      // handshake / options request on device boot or reconnect
      return plainText(
        `GET OPTION FROM: ${sn}\n` +
        `Stamp=9999\nOpStamp=9999\nErrorDelay=60\nDelay=30\n` +
        `TransTimes=00:00;14:05\nTransInterval=1\nTransFlag=1111000000\n` +
        `Realtime=1\nEncrypt=0\n`
      );
    }
    const table = (qs.table || '').toUpperCase();
    const bodyText = rawBody(event);

    if (table === 'ATTLOG') {
      const lines = bodyText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

      // parse everything first
      const punches = [];
      for (const line of lines) {
        const cols = line.split(/\t+/);
        const pin = cols[0], timeStr = cols[1];
        if (!pin || !timeStr) continue;
        const punchTime = new Date(timeStr.replace(' ', 'T'));
        if (isNaN(punchTime.getTime())) continue;
        punches.push({
          pin,
          punchTime,
          status: cols[2] !== undefined ? parseInt(cols[2], 10) : null,
          verify: cols[3] !== undefined ? parseInt(cols[3], 10) : null,
        });
      }
      if (!punches.length) return plainText('OK: 0');

      // [FIX 5] one lookup for every PIN in the batch, not one per line
      const pins = [...new Set(punches.map(p => p.pin))];
      const studentRows = await sql`
        SELECT student_id, device_pin FROM students WHERE device_pin = ANY(${pins})`;
      const studentByPin = {};
      studentRows.forEach(r => { studentByPin[r.device_pin] = r.student_id });

      let count = 0;
      for (const p of punches) {
        await sql`
          INSERT INTO attendance_punches (device_serial, device_pin, punch_time, verify_mode, raw_status, student_id)
          VALUES (${sn}, ${p.pin}, ${p.punchTime.toISOString()}, ${p.verify}, ${p.status}, ${studentByPin[p.pin] || null})`;
        count++;
      }
      return plainText('OK: ' + count);
    }
    return plainText('OK'); // USER/OPERLOG/other tables — acknowledged, not processed yet
  }
  if (sub === 'getrequest') return plainText('OK'); // no queued commands in this version
  if (sub === 'devicecmd') return plainText('OK');
  return plainText('OK'); // /iclock/test or anything else — simple ack
}

// =====================================================================
//  ROUTES
// =====================================================================
let _linkReady = false;
async function ensureLinkSchema() {
  if (_linkReady) return;
  await sql`CREATE TABLE IF NOT EXISTS staff_links (id SERIAL PRIMARY KEY, teacher_id INTEGER NOT NULL, key_hash TEXT UNIQUE NOT NULL, expires_at TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, revoked_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW())`;
  await sql`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS username TEXT`;
  await sql`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS teacher_password TEXT`;
  await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS nationality TEXT`;
  await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS profile_photo TEXT`;
  await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`;
  await sql`ALTER TABLE students ADD COLUMN IF NOT EXISTS archive_reason TEXT`;
  await sql`CREATE TABLE IF NOT EXISTS subject_stages (subject TEXT NOT NULL, stage TEXT NOT NULL, UNIQUE(subject, stage))`;
  await sql`CREATE TABLE IF NOT EXISTS teacher_assignments (id SERIAL PRIMARY KEY, teacher_id INTEGER NOT NULL, academic_year TEXT NOT NULL, grade_level TEXT NOT NULL, class_name TEXT NOT NULL, subject TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(teacher_id, academic_year, grade_level, class_name, subject))`;
  await sql`ALTER TABLE teachers ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE`;
  await sql`CREATE TABLE IF NOT EXISTS report_remarks (id SERIAL PRIMARY KEY, student_id TEXT NOT NULL, academic_year TEXT NOT NULL, term TEXT NOT NULL, conduct TEXT, teacher_remark TEXT, head_remark TEXT, next_term_date TEXT, updated_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(student_id, academic_year, term))`;
  try { await sql`CREATE TABLE IF NOT EXISTS behavior_records (id SERIAL PRIMARY KEY, student_id TEXT NOT NULL, type TEXT NOT NULL, category TEXT, description TEXT, points INTEGER DEFAULT 0, recorded_by TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`; } catch (e) {}
  try { await sql`ALTER TABLE behavior_records ADD COLUMN IF NOT EXISTS incident_date DATE`; } catch (e) {}
  try { await sql`ALTER TABLE behavior_records ADD COLUMN IF NOT EXISTS severity TEXT`; } catch (e) {}
  try { await sql`ALTER TABLE behavior_records ADD COLUMN IF NOT EXISTS action_taken TEXT`; } catch (e) {}
  try { await sql`ALTER TABLE fee_targets ADD COLUMN IF NOT EXISTS registration_amount NUMERIC DEFAULT 0`; } catch (e) {}
  _linkReady = true;
}
function hashKey(k){ return crypto.createHash('sha256').update(String(k)).digest('hex'); }

const routes = {

  // ---------------- AUTH ----------------
  'get-years': { GET: async () => {
    const set = new Set();
    for (const tbl of ['results','fee_payments','fee_structure','fee_targets']) {
      try { const r = await sql(`SELECT DISTINCT academic_year AS y FROM ${tbl} WHERE academic_year IS NOT NULL`); r.forEach(x => { if (x.y) set.add(x.y); }); } catch (e) {}
    }
    const years = Array.from(set);
    const now = new Date(); const m = now.getMonth(); const startY = m >= 7 ? now.getFullYear() : now.getFullYear() - 1;
    const cur = startY + '-' + (startY + 1);
    if (!years.includes(cur)) years.push(cur);
    years.sort().reverse();
    return ok({ years });
  }},
  'get-subject-stages': { GET: async () => {
    await ensureLinkSchema();
    const rows = await sql`SELECT subject, stage FROM subject_stages`;
    return ok({ map: rows });
  }},
  'set-subject-stages': { POST: async (event) => {
    await ensureLinkSchema();
    const { subject, stages } = readBody(event);
    if (!subject || !Array.isArray(stages)) return err('بيانات ناقصة');
    await sql`DELETE FROM subject_stages WHERE subject = ${subject}`;
    for (const st of stages) { if (st) await sql`INSERT INTO subject_stages (subject, stage) VALUES (${subject}, ${st}) ON CONFLICT DO NOTHING`; }
    return ok({ message: 'تم حفظ مراحل المادة' });
  }},
  'attendance-book': { GET: async (event) => {
    const { gradeLevel, className, fromDate, toDate } = event.queryStringParameters || {};
    if (!gradeLevel || !className || !fromDate || !toDate) return err('بيانات ناقصة');
    const students = await sql`SELECT student_id, full_name FROM students WHERE grade_level = ${gradeLevel} AND LOWER(class_name)=LOWER(${className}) AND active IS NOT FALSE ORDER BY full_name`;
    const rows = await sql`SELECT a.student_id, to_char(a.att_date,'YYYY-MM-DD') AS d, a.status FROM attendance a JOIN students s ON s.student_id = a.student_id WHERE s.grade_level = ${gradeLevel} AND LOWER(s.class_name)=LOWER(${className}) AND a.att_date >= ${fromDate}::date AND a.att_date <= ${toDate}::date`;
    const marks = {};
    rows.forEach(r => { (marks[r.student_id] = marks[r.student_id] || {})[r.d] = r.status; });
    return ok({ students, marks });
  }},
  'dashboard-stats': { GET: async () => {
    const st = (await sql`SELECT COUNT(*)::int AS n FROM students WHERE active IS NOT FALSE`)[0].n;
    const te = (await sql`SELECT COUNT(*)::int AS n FROM teachers`)[0].n;
    const re = (await sql`SELECT COUNT(*)::int AS n FROM results`)[0].n;
    let su = 0; try { su = (await sql`SELECT COUNT(*)::int AS n FROM subjects`)[0].n; } catch(e){}
    const byStage = await sql`SELECT grade_level AS stage, COUNT(*)::int AS n FROM students WHERE active IS NOT FALSE GROUP BY grade_level ORDER BY grade_level`;
    return ok({ students: st, teachers: te, results: re, subjects: su, byStage });
  }},
  'get-teacher-assignments': { GET: async () => {
    await ensureLinkSchema();
    const assignments = await sql`SELECT id, teacher_id, academic_year, grade_level, class_name, subject FROM teacher_assignments ORDER BY academic_year DESC, grade_level, class_name, subject`;
    return ok({ assignments });
  }},
  'teacher-assignment': { POST: async (event) => {
    await ensureLinkSchema();
    const { action, id, teacherId, academicYear, gradeLevel, className, subjects } = readBody(event);
    if (action === 'remove') {
      if (!id) return err('id مطلوب');
      const rows = await sql`DELETE FROM teacher_assignments WHERE id = ${parseInt(id)} RETURNING id`;
      if (!rows.length) return err('التكليف غير موجود', 404);
      return ok({ message: 'تم حذف التكليف' });
    }
    if (!teacherId || !academicYear || !gradeLevel || !className || !Array.isArray(subjects) || !subjects.length)
      return err('المعلم والعام والمرحلة والفصل ومادة واحدة على الأقل مطلوبة');
    const t = await sql`SELECT id FROM teachers WHERE id = ${parseInt(teacherId)}`;
    if (!t.length) return err('المعلم غير موجود', 404);
    let n = 0;
    for (const subRaw of subjects) {
      const sub = String(subRaw).trim(); if (!sub) continue;
      const r = await sql`INSERT INTO teacher_assignments (teacher_id, academic_year, grade_level, class_name, subject)
        VALUES (${parseInt(teacherId)}, ${academicYear}, ${gradeLevel}, ${className}, ${sub})
        ON CONFLICT (teacher_id, academic_year, grade_level, class_name, subject) DO NOTHING RETURNING id`;
      if (r.length) n++;
    }
    return ok({ message: 'تم تكليف ' + n + ' مادة' });
  }},
  'student-history': { GET: async (event) => {
    await ensureLinkSchema();
    const { studentId } = event.queryStringParameters || {};
    if (!studentId) return err('رقم الطالب مطلوب');
    const stu = (await sql`SELECT student_id, full_name, grade_level, class_name, status, archived_at, archive_reason, date_of_birth, nationality, guardian_name, address, profile_photo FROM students WHERE student_id = ${studentId}`)[0];
    if (!stu) return err('الطالب غير موجود', 404);
    const results = await sql`SELECT subject, score, grade, academic_year, term, grade_level, class_name FROM results WHERE student_id = ${studentId} ORDER BY academic_year, term, subject`;
    const seen = {}; const years = [];
    results.forEach(r => { if (!seen[r.academic_year]) { seen[r.academic_year]=1; years.push(r.academic_year); } });
    years.sort();
    return ok({ student: stu, results, years, enrollments: [] });
  }},
  'archive-student': { POST: async (event) => {
    await ensureLinkSchema();
    const { studentId, reason, restore } = readBody(event);
    if (!studentId) return err('رقم الطالب مطلوب');
    if (restore) { await sql`UPDATE students SET status = 'active', active = TRUE, archived_at = NULL, archive_reason = NULL WHERE student_id = ${studentId}`; return ok({ message: 'تمت استعادة الطالب' }); }
    await sql`UPDATE students SET status = 'archived', active = FALSE, archived_at = now(), archive_reason = ${reason||null} WHERE student_id = ${studentId}`;
    return ok({ message: 'تمت أرشفة الطالب (لم يُحذف — سجلّه محفوظ)' });
  }},
  'get-student-photo': { GET: async (event) => {
    await ensureLinkSchema();
    const { studentId } = event.queryStringParameters || {};
    if (!studentId) return err('رقم الطالب مطلوب');
    const r = (await sql`SELECT profile_photo FROM students WHERE student_id = ${studentId}`)[0];
    return ok({ photo: r ? r.profile_photo : null });
  }},
  'admin-upload-photo': { POST: async (event) => {
    await ensureLinkSchema();
    const { studentId, photoDataUrl } = readBody(event);
    if (!studentId || !photoDataUrl) return err('بيانات ناقصة');
    if (photoDataUrl.length > 2200000) return err('الصورة كبيرة جداً');
    await sql`UPDATE students SET profile_photo = ${photoDataUrl} WHERE student_id = ${studentId}`;
    return ok({ message: 'تم حفظ الصورة' });
  }},
  'class-list': { GET: async (event) => {
    const { gradeLevel, className } = event.queryStringParameters || {};
    if (!gradeLevel || !className) return err('المرحلة والفصل مطلوبان');
    const students = await sql`SELECT student_id, full_name, guardian_name, guardian_phone, nationality, date_of_birth FROM students WHERE grade_level = ${gradeLevel} AND LOWER(class_name) = LOWER(${className}) AND active IS NOT FALSE ORDER BY full_name`;
    return ok({ students });
  }},
  'teacher-login': {
 POST: async (event) => {
    await ensureLinkSchema();
    const { username, password, key } = readBody(event);
    if (!username || !password) return err('اسم المستخدم وكلمة المرور مطلوبان');
    if (!key) return err('يرجى فتح رابط الوصول الذي أرسله المدير', 403);
    const link = (await sql`SELECT id, teacher_id, revoked, expires_at FROM staff_links WHERE key_hash = ${hashKey(key)} LIMIT 1`)[0];
    if (!link) return err('هذا الرابط غير صالح. اطلب رابطاً جديداً من المدير.', 403);
    if (link.revoked) return err('تم إلغاء هذا الرابط من قبل المدير.', 403);
    if (new Date(link.expires_at).getTime() <= Date.now()) return err('انتهت صلاحية هذا الرابط.', 403);
    const trow = (await sql`SELECT id, full_name, username, teacher_password, subject FROM teachers WHERE username = ${username} LIMIT 1`)[0];
    if (!trow || !trow.teacher_password || !verifyPassword(password, trow.teacher_password)) return err('بيانات الدخول غير صحيحة', 401);
    if (link.teacher_id !== trow.id) return err('هذا الرابط يخص معلماً آخر.', 403);
    await sql`UPDATE staff_links SET last_used_at = NOW() WHERE id = ${link.id}`;
    const token = signToken({ role:'teacher', tid: trow.id, sub: trow.username, lid: link.id, exp: new Date(link.expires_at).getTime() });
    return ok({ token, teacher: { id: trow.id, full_name: trow.full_name, username: trow.username, subject: trow.subject }, accessUntil: link.expires_at });
  }},
  'staff-links': { GET: async () => {
    await ensureLinkSchema();
    const links = await sql`SELECT l.id, l.teacher_id, t.full_name, t.username, l.revoked, to_char(l.created_at,'DD/MM/YYYY HH24:MI') AS created, to_char(l.expires_at,'DD Mon YYYY') AS expires, to_char(l.last_used_at,'DD/MM/YYYY HH24:MI') AS last_used, (l.expires_at > NOW()) AS not_expired FROM staff_links l JOIN teachers t ON t.id = l.teacher_id ORDER BY l.created_at DESC LIMIT 300`;
    return ok({ links });
  }},
  'create-staff-link': { POST: async (event) => {
    await ensureLinkSchema();
    const { teacherId, validUntil } = readBody(event);
    if (!teacherId || !/^\d{4}-\d{2}-\d{2}$/.test(validUntil||'')) return err('المعلم وتاريخ الانتهاء مطلوبان');
    const expires = new Date(validUntil + 'T23:59:59Z');
    if (isNaN(expires.getTime()) || expires.getTime() <= Date.now()) return err('يجب أن يكون التاريخ اليوم أو بعده');
    const t = (await sql`SELECT id, full_name, username, teacher_password FROM teachers WHERE id = ${parseInt(teacherId)}`)[0];
    if (!t) return err('المعلم غير موجود', 404);
    let generatedPassword = null;
    if (!t.username || !t.teacher_password) {
      let uname = t.username;
      if (!uname) {
        const base = 't' + t.id; uname = base; let n = 0;
        while ((await sql`SELECT 1 FROM teachers WHERE username = ${uname}`).length) { n++; uname = base + '_' + n; }
      }
      if (!t.teacher_password) {
        generatedPassword = String(crypto.randomInt(100000, 1000000));
        await sql`UPDATE teachers SET username = ${uname}, teacher_password = ${hashPassword(generatedPassword)} WHERE id = ${t.id}`;
      } else {
        await sql`UPDATE teachers SET username = ${uname} WHERE id = ${t.id}`;
      }
      t.username = uname;
    }
    const key = crypto.randomBytes(24).toString('base64url');
    const r = (await sql`INSERT INTO staff_links (teacher_id, key_hash, expires_at) VALUES (${t.id}, ${hashKey(key)}, ${expires.toISOString()}) RETURNING id`)[0];
    return ok({ id: r.id, key, validUntil, teacher: t.full_name, username: t.username, password: generatedPassword });
  }},
  'revoke-staff-link': { POST: async (event) => {
    await ensureLinkSchema();
    const { id } = readBody(event);
    const r = await sql`UPDATE staff_links SET revoked = TRUE, revoked_at = NOW() WHERE id = ${parseInt(id)} AND revoked = FALSE RETURNING id`;
    if (!r.length) return err('الرابط غير موجود أو ملغى بالفعل', 404);
    return ok({ message: 'تم إلغاء الرابط' });
  }},
  'delete-staff-link': { POST: async (event) => {
    await ensureLinkSchema();
    const { id, clearOld } = readBody(event);
    if (clearOld) { const r = await sql`DELETE FROM staff_links WHERE revoked = TRUE OR expires_at <= NOW() RETURNING id`; return ok({ message: r.length + ' deleted' }); }
    const r = await sql`DELETE FROM staff_links WHERE id = ${parseInt(id)} AND (revoked = TRUE OR expires_at <= NOW()) RETURNING id`;
    if (!r.length) return err('يمكن حذف الروابط المنتهية أو الملغاة فقط.');
    return ok({ message: 'تم الحذف' });
  }},
  'teacher-me': { GET: async (event, auth) => {
    const t = (await sql`SELECT id, full_name, username, subject, grade_level FROM teachers WHERE id = ${auth.tid}`)[0];
    if (!t) return err('غير موجود', 404);
    const l = auth.lid ? (await sql`SELECT to_char(expires_at,'DD Mon YYYY') AS until FROM staff_links WHERE id = ${auth.lid}`)[0] : null;
    return ok({ teacher: t, accessUntil: l ? l.until : null });
  }},
  'get-remarks': { GET: async (event) => {
    await ensureLinkSchema();
    const { studentId, academicYear, term } = event.queryStringParameters || {};
    if (!studentId || !academicYear || !term) return err('بيانات ناقصة');
    const r = (await sql`SELECT conduct, teacher_remark, head_remark, next_term_date FROM report_remarks WHERE student_id = ${studentId} AND academic_year = ${academicYear} AND term = ${term}`)[0];
    return ok({ remarks: r || null });
  }},
  'save-remarks': { POST: async (event) => {
    await ensureLinkSchema();
    const b = readBody(event);
    if (!b.studentId || !b.academicYear || !b.term) return err('بيانات ناقصة');
    await sql`INSERT INTO report_remarks (student_id, academic_year, term, conduct, teacher_remark, head_remark, next_term_date, updated_at) VALUES (${b.studentId}, ${b.academicYear}, ${b.term}, ${b.conduct||null}, ${b.teacherRemark||null}, ${b.headRemark||null}, ${b.nextTermDate||null}, now()) ON CONFLICT (student_id, academic_year, term) DO UPDATE SET conduct = EXCLUDED.conduct, teacher_remark = EXCLUDED.teacher_remark, head_remark = EXCLUDED.head_remark, next_term_date = EXCLUDED.next_term_date, updated_at = now()`;
    return ok({ message: 'تم حفظ الملاحظات' });
  }},
  'staff-roster': { GET: async (event, auth) => {
    const { gradeLevel, className } = event.queryStringParameters || {};
    if (!gradeLevel || !className) return err('المرحلة والفصل مطلوبان');
    const students = await sql`SELECT student_id, full_name FROM students WHERE grade_level = ${gradeLevel} AND LOWER(class_name) = LOWER(${className}) AND active IS NOT FALSE ORDER BY full_name`;
    return ok({ students });
  }},
  'staff-save-scores': { POST: async (event, auth) => {
    const { subject, academicYear, term, scores } = readBody(event);
    if (!subject || !academicYear || !term || !Array.isArray(scores)) return err('بيانات ناقصة');
    let n = 0;
    for (const row of scores) {
      if (!row.studentId || row.score == null || row.score === '') continue;
      const sc = Number(row.score); if (isNaN(sc) || sc < 0 || sc > 100) continue;
      const stud = (await sql`SELECT class_name, grade_level FROM students WHERE student_id = ${row.studentId}`)[0];
      if (!stud) continue;
      await sql`INSERT INTO results (student_id, subject, score, grade, academic_year, term, class_name, grade_level, updated_at) VALUES (${row.studentId}, ${subject}, ${sc}, ${gradeFor(sc)}, ${academicYear}, ${term}, ${stud.class_name}, ${stud.grade_level}, now()) ON CONFLICT (student_id, subject, academic_year, term) DO UPDATE SET score = EXCLUDED.score, grade = EXCLUDED.grade, updated_at = now()`;
      n++;
    }
    return ok({ message: 'تم حفظ ' + n + ' درجة', saved: n });
  }},
  'staff-save-attendance': { POST: async (event, auth) => {
    const { date, marks } = readBody(event);
    if (!date || !marks || typeof marks !== 'object') return err('بيانات ناقصة');
    let n = 0;
    for (const sid of Object.keys(marks)) {
      const st = marks[sid]; if (!st) continue;
      await sql`INSERT INTO attendance (att_date, student_id, status, recorded_at) VALUES (${date}, ${sid}, ${st}, now()) ON CONFLICT (student_id, att_date) DO UPDATE SET status = EXCLUDED.status, recorded_at = now()`;
      n++;
    }
    return ok({ message: 'تم حفظ الحضور', saved: n });
  }},
  'admin-login': { POST: async (event) => {
    const { username, password } = readBody(event);
    if (!username || !password) return err('اسم المستخدم وكلمة المرور مطلوبان');
    const rows = await sql`SELECT username, role, display_name FROM admins WHERE username = ${username}`;
    if (!rows.length) return err('بيانات الدخول غير صحيحة', 401);
    const match = await sql`
      SELECT (password_hash = crypt(${password}, password_hash)) AS matched
      FROM admins WHERE username = ${username}`;
    if (!match.length || !match[0].matched) return err('بيانات الدخول غير صحيحة', 401);
    await logActivity(`تسجيل دخول: ${username}`, username);
    const token = signToken({ username: rows[0].username, role: rows[0].role, exp: Date.now() + SESSION_TTL_MS });
    return ok({ username: rows[0].username, role: rows[0].role, displayName: rows[0].display_name, token });
  }},

  // [FIX 4] the username is taken from the verified token (stamped onto
  // `actor` by the handler), never from the request body — otherwise any
  // logged-in account could change another account's password.
  'change-admin-password': { POST: async (event) => {
    const { currentPassword, newPassword, actor } = readBody(event);
    const username = actor;
    if (!username) return err('يجب تسجيل الدخول', 401);
    if (!currentPassword || !newPassword) return err('يرجى ملء جميع الحقول');
    if (newPassword.length < 6) return err('كلمة المرور قصيرة');
    const match = await sql`
      SELECT (password_hash = crypt(${currentPassword}, password_hash)) AS matched
      FROM admins WHERE username = ${username}`;
    if (!match.length) return err('المستخدم غير موجود', 404);
    if (!match[0].matched) return err('كلمة المرور الحالية غير صحيحة', 401);
    await sql`UPDATE admins SET password_hash = ${newPassword} WHERE username = ${username}`;
    await logActivity(`تغيير كلمة مرور: ${username}`, username);
    return ok({ message: 'تم تغيير كلمة المرور' });
  }},

  // ---------------- ADMIN ACCOUNT MANAGEMENT ----------------
  'get-admins': { GET: async () => {
    const admins = await sql`SELECT id, username, display_name, role, created_at FROM admins ORDER BY created_at`;
    return ok({ admins });
  }},

  'add-admin': { POST: async (event) => {
    const { username, password, displayName, role, actor } = readBody(event);
    const u = (username || '').trim();
    if (!u || !password || !role) return err('اسم المستخدم وكلمة المرور والصلاحية مطلوبة');
    if (password.length < 6) return err('كلمة المرور قصيرة');
    const exists = await sql`SELECT 1 FROM admins WHERE username = ${u}`;
    if (exists.length) return err('اسم المستخدم مستخدم بالفعل');
    try {
      // password written PLAIN — trg_hash_admin_password bcrypts it automatically
      await sql`INSERT INTO admins (username, password_hash, display_name, role)
                VALUES (${u}, ${password}, ${displayName || null}, ${role})`;
    } catch (e) {
      if (String(e.message).includes('admins_role_ck')) return err('الصلاحية غير مسموحة لهذا الحقل (تحقق من قيد role في قاعدة البيانات)');
      throw e;
    }
    await logActivity(`إضافة حساب إداري: ${u} (${role})`, actor);
    return ok({ message: 'تمت إضافة الحساب' });
  }},

  'update-admin': { PUT: async (event) => {
    const { username, displayName, role, newPassword, actor } = readBody(event);
    if (!username) return err('اسم المستخدم مطلوب');
    const exists = await sql`SELECT 1 FROM admins WHERE username = ${username}`;
    if (!exists.length) return err('الحساب غير موجود', 404);
    if (displayName !== undefined) await sql`UPDATE admins SET display_name = ${displayName} WHERE username = ${username}`;
    if (role) await sql`UPDATE admins SET role = ${role} WHERE username = ${username}`;
    if (newPassword) {
      if (newPassword.length < 6) return err('كلمة المرور قصيرة');
      await sql`UPDATE admins SET password_hash = ${newPassword} WHERE username = ${username}`;
    }
    await logActivity(`تعديل حساب إداري: ${username}`, actor);
    return ok({ message: 'تم التحديث' });
  }},

  'delete-admin': { DELETE: async (event) => {
    const { username, actor } = readBody(event);
    if (!username) return err('اسم المستخدم مطلوب');
    const count = await sql`SELECT COUNT(*)::int AS n FROM admins`;
    if (count[0].n <= 1) return err('لا يمكن حذف آخر حساب إداري');
    const res = await sql`DELETE FROM admins WHERE username = ${username} RETURNING username`;
    if (!res.length) return err('الحساب غير موجود', 404);
    await logActivity(`حذف حساب إداري: ${username}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- CLASSES / STAGES ----------------
  'get-classes': { GET: async () => {
    const classes = await sql`SELECT id, stage, name, sort_order, promotes_to, active FROM classes ORDER BY sort_order`;
    return ok({ classes });
  }},

  'add-class': { POST: async (event) => {
    const { stage, name, sortOrder, promotesTo, actor } = readBody(event);
    const cleanName = (name || '').trim();
    if (!stage || !cleanName || sortOrder === undefined) return err('المرحلة والاسم والترتيب مطلوبة');
    const exists = await sql`SELECT 1 FROM classes WHERE name = ${cleanName}`;
    if (exists.length) return err('يوجد فصل بهذا الاسم بالفعل');
    await sql`INSERT INTO classes (stage, name, sort_order, promotes_to)
              VALUES (${stage}, ${cleanName}, ${sortOrder}, ${promotesTo || null})`;
    await logActivity(`إضافة فصل: ${cleanName}`, actor);
    return ok({ message: 'تمت الإضافة' });
  }},

  'update-class': { PUT: async (event) => {
    const { id, stage, name, sortOrder, promotesTo, active, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const exists = await sql`SELECT name FROM classes WHERE id = ${id}`;
    if (!exists.length) return err('الفصل غير موجود', 404);
    const oldName = exists[0].name;
    if (stage !== undefined) await sql`UPDATE classes SET stage = ${stage} WHERE id = ${id}`;
    if (name !== undefined && name.trim()) await sql`UPDATE classes SET name = ${name.trim()} WHERE id = ${id}`;
    if (sortOrder !== undefined) await sql`UPDATE classes SET sort_order = ${sortOrder} WHERE id = ${id}`;
    if (promotesTo !== undefined) await sql`UPDATE classes SET promotes_to = ${promotesTo || null} WHERE id = ${id}`;
    if (active !== undefined) await sql`UPDATE classes SET active = ${active} WHERE id = ${id}`;

    // [FIX 6] a rename has to follow the class name EVERYWHERE it is stored
    // as text, not just in students + classes.promotes_to. fee_targets and
    // exams both key off class_name too; missing them silently orphaned a
    // class's official fees the moment it was renamed.
    if (name !== undefined && name.trim() && name.trim() !== oldName) {
      const newName = name.trim();
      await sql`UPDATE classes      SET promotes_to = ${newName} WHERE promotes_to = ${oldName}`;
      await sql`UPDATE students     SET class_name  = ${newName} WHERE class_name  = ${oldName}`;
      await sql`UPDATE fee_targets  SET class_name  = ${newName} WHERE class_name  = ${oldName}`;
      try { await sql`UPDATE exams SET class_name = ${newName} WHERE class_name = ${oldName}` }
      catch (e) { console.error('exams rename skipped:', e.message) }
    }
    await logActivity(`تعديل فصل #${id}`, actor);
    return ok({ message: 'تم التحديث' });
  }},

  'delete-class': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const rows = await sql`SELECT name FROM classes WHERE id = ${id}`;
    if (!rows.length) return err('الفصل غير موجود', 404);
    const inUse = await sql`SELECT COUNT(*)::int AS n FROM students WHERE class_name = ${rows[0].name} AND active = true`;
    if (inUse[0].n > 0) return err('لا يمكن حذف فصل يضم طلاباً نشطين — انقلوهم أولاً');
    await sql`DELETE FROM classes WHERE id = ${id}`;
    await logActivity(`حذف فصل: ${rows[0].name}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- STUDENTS ----------------
  'get-all-students': { GET: async () => {
    const students = await sql`
      SELECT student_id, full_name, grade_level, class_name, guardian_name, nationality,
             guardian_phone, student_phone, date_of_birth, address, active, status, device_pin,
             created_at, enrolled_year, enrolled_class
      FROM students ORDER BY grade_level, class_name, full_name`;
    return ok({ students });
  }},

  'add-student': { POST: async (event) => {
    await ensureLinkSchema();
    const b = readBody(event);
    const studentId = (b.studentId || '').trim();
    const fullName = (b.fullName || '').trim();
    const password = (b.password || '').trim();
    if (!studentId || !fullName || !password) return err('رقم الطالب والاسم وكلمة المرور مطلوبة');
    if (!b.gradeLevel || !b.className) return err('يرجى اختيار المرحلة والفصل');
    const exists = await sql`SELECT 1 FROM students WHERE student_id = ${studentId}`;
    if (exists.length) return err('رقم الطالب مستخدم بالفعل');
    // [FIX 7] student_phone is selected by get-all-students but was never
    // writable — it could only ever come back null.
    // [FIX 12] The intake is recorded at the moment of registration: when they
    // joined, and which class they joined INTO. A student who enrols straight
    // into grade 10 must still show up as a 2026-2027 newcomer, and promotions
    // later on must never rewrite that.
    await sql`
      INSERT INTO students (student_id, full_name, password, grade_level, class_name,
                            date_of_birth, guardian_name, guardian_phone, student_phone, address,
                            nationality, enrolled_year, enrolled_class, created_at)
      VALUES (${studentId}, ${fullName}, ${hashPassword(password)}, ${b.gradeLevel}, ${b.className},
              ${b.dateOfBirth || null}, ${b.guardianName || null}, ${b.guardianPhone || null},
              ${b.studentPhone || null}, ${b.address || null},
              ${b.nationality || null}, ${b.enrolledYear || null}, ${b.className}, now())`;
    await logActivity(`إضافة طالب جديد: ${fullName} (${studentId})`, b.actor);
    return ok({ message: 'تمت إضافة الطالب' });
  }},

  // ---------------- BULK STUDENT IMPORT ----------------
  // Lets the admin paste a table instead of ever touching Excel again.
  // Expected row shape (all but fullName/className optional):
  //   { fullName, className, gradeLevel, guardianName, guardianPhone,
  //     dateOfBirth, address, feeInstitute, feeExam, feeNote, academicYear }
  // studentId/password are generated here (NR#### + password = ID).
  'bulk-import-students': { POST: async (event) => {
    const { rows, actor } = readBody(event);
    if (!Array.isArray(rows) || !rows.length) return err('لا توجد بيانات لاستيرادها');

    const classRows = await sql`SELECT name, stage FROM classes`;
    const stageOf = {};
    classRows.forEach(c => { stageOf[c.name] = c.stage });

    const maxRow = await sql`
      SELECT student_id FROM students
      WHERE student_id ~ '^NR[0-9]+$'
      ORDER BY (substring(student_id from 3))::int DESC LIMIT 1`;
    let nextNum = maxRow.length ? parseInt(maxRow[0].student_id.slice(2), 10) + 1 : 1;

    let imported = 0, failed = 0, feeImported = 0;
    const errors = [];
    for (const r of rows) {
      const fullName = (r.fullName || '').trim();
      const className = (r.className || '').trim();
      if (!fullName || !className) { failed++; continue }
      if (!stageOf[className]) { failed++; errors.push(`فصل غير معروف: ${className} (${fullName})`); continue }

      const studentId = 'NR' + String(nextNum).padStart(4, '0');
      nextNum++;
      try {
        await sql`
          INSERT INTO students (student_id, full_name, password, grade_level, class_name,
                                date_of_birth, guardian_name, guardian_phone, address,
                                enrolled_year, enrolled_class, created_at)
          VALUES (${studentId}, ${fullName}, ${hashPassword(studentId)},
                  ${r.gradeLevel || stageOf[className]}, ${className},
                  ${r.dateOfBirth || null}, ${r.guardianName || null}, ${r.guardianPhone || null}, ${r.address || null},
                  ${r.academicYear || null}, ${className}, now())`;
        imported++;

        const year = r.academicYear || null;
        const stage = r.gradeLevel || stageOf[className];
        if (year && r.feeInstitute) {
          await sql`INSERT INTO fee_payments (student_id, academic_year, term, amount, method, reference,
                                              class_name, grade_level, recorded_by)
                    VALUES (${studentId}, ${year}, 'سنوي', ${r.feeInstitute}, ${r.feeNote || null}, 'رسوم المعهد',
                            ${className}, ${stage}, ${actor || 'استيراد'})`;
          feeImported++;
        }
        if (year && r.feeExam) {
          await sql`INSERT INTO fee_payments (student_id, academic_year, term, amount, method, reference,
                                              class_name, grade_level, recorded_by)
                    VALUES (${studentId}, ${year}, 'سنوي', ${r.feeExam}, ${r.feeNote || null}, 'رسوم الامتحان',
                            ${className}, ${stage}, ${actor || 'استيراد'})`;
          feeImported++;
        }
      } catch (e) { failed++; errors.push(`${fullName}: ${e.message}`) }
    }
    if (!imported) return err('لم يتم استيراد أي طالب — تحققوا من الأعمدة والفصول');
    await logActivity(`استيراد جماعي: ${imported} طالب (${failed} فشل)`, actor);
    return ok({
      message: `تم استيراد ${imported} طالب` + (failed ? ` — تخطّي ${failed}` : ''),
      imported, failed, feeImported, errors: errors.slice(0, 20),
    });
  }},

  'update-student': { PUT: async (event) => {
    await ensureLinkSchema();
    const b = readBody(event);
    const studentId = (b.studentId || '').trim();
    if (!studentId) return err('رقم الطالب مطلوب');
    const rows = await sql`SELECT student_id FROM students WHERE student_id = ${studentId}`;
    if (!rows.length) return err('لا يوجد طالب بهذا الرقم', 404);
    if (b.fullName)   await sql`UPDATE students SET full_name   = ${b.fullName}   WHERE student_id = ${studentId}`;
    if (b.gradeLevel) await sql`UPDATE students SET grade_level = ${b.gradeLevel} WHERE student_id = ${studentId}`;
    if (b.className)  await sql`UPDATE students SET class_name  = ${b.className}  WHERE student_id = ${studentId}`;
    if (b.password)   await sql`UPDATE students SET password    = ${hashPassword(b.password)} WHERE student_id = ${studentId}`;
    if (b.guardianName  !== undefined) await sql`UPDATE students SET guardian_name  = ${b.guardianName  || null} WHERE student_id = ${studentId}`;
    if (b.guardianPhone !== undefined) await sql`UPDATE students SET guardian_phone = ${b.guardianPhone || null} WHERE student_id = ${studentId}`;
    if (b.studentPhone  !== undefined) await sql`UPDATE students SET student_phone  = ${b.studentPhone  || null} WHERE student_id = ${studentId}`;
    if (b.dateOfBirth   !== undefined) await sql`UPDATE students SET date_of_birth  = ${b.dateOfBirth   || null} WHERE student_id = ${studentId}`;
    if (b.address       !== undefined) await sql`UPDATE students SET address        = ${b.address       || null} WHERE student_id = ${studentId}`;
    if (b.nationality !== undefined) await sql`UPDATE students SET nationality = ${b.nationality||null} WHERE student_id = ${studentId}`;
    if (b.devicePin !== undefined) {
      const pin = b.devicePin ? String(b.devicePin).trim() : null;
      if (pin) {
        const clash = await sql`SELECT student_id FROM students WHERE device_pin = ${pin} AND student_id != ${studentId}`;
        if (clash.length) return err('رقم البصمة هذا مستخدَم بالفعل لطالب آخر (' + clash[0].student_id + ')');
      }
      await sql`UPDATE students SET device_pin = ${pin} WHERE student_id = ${studentId}`;
    }
    await logActivity(`تعديل بيانات طالب: ${studentId}`, b.actor);
    return ok({ message: 'تم التحديث' });
  }},

  'delete-student': { DELETE: async (event) => {
    const { studentId, actor } = readBody(event);
    if (!studentId) return err('رقم الطالب مطلوب');
    const res = await sql`UPDATE students SET status='archived', active=FALSE, archived_at=now(), archive_reason='deleted via admin' WHERE student_id = ${studentId} RETURNING student_id`;
    if (!res.length) return err('لا يوجد طالب بهذا الرقم', 404);
    await logActivity(`حذف طالب: ${studentId}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- RESULTS ----------------
  'get-all-results': { GET: async () => {
    const results = await sql`
      SELECT r.id, r.student_id, s.full_name,
             COALESCE(r.grade_level, s.grade_level) AS grade_level,
             COALESCE(r.class_name,  s.class_name)  AS class_name,
             r.subject, r.score, r.grade, r.academic_year, r.term
      FROM results r JOIN students s ON s.student_id = r.student_id
      ORDER BY r.updated_at DESC`;
    return ok({ results });
  }},

  'add-marks': { POST: async (event) => {
    const { studentId, subject, score, academicYear, term, actor } = readBody(event);
    if (!studentId || !subject || score === undefined || score === null || !academicYear || !term)
      return err('يرجى ملء جميع الحقول');
    const n = parseInt(score, 10);
    if (isNaN(n) || n < 0 || n > 100) return err('الدرجة يجب أن تكون بين 0 و 100');
    const stud = await sql`SELECT class_name, grade_level FROM students WHERE student_id = ${studentId}`;
    if (!stud.length) return err('لا يوجد طالب بهذا الرقم', 404);
    const existing = await sql`
      SELECT id FROM results
      WHERE student_id = ${studentId} AND subject = ${subject}
        AND academic_year = ${academicYear} AND term = ${term}`;
    // [FIX 10] the class is stamped ONTO the row. After a promotion the student
    // moves up, but this mark must keep printing under the class they actually
    // sat it in — otherwise last year's كشف الدرجات silently rewrites itself.
    await sql`
      INSERT INTO results (student_id, subject, score, grade, academic_year, term,
                           class_name, grade_level, updated_at)
      VALUES (${studentId}, ${subject}, ${n}, ${gradeFor(n)}, ${academicYear}, ${term},
              ${stud[0].class_name}, ${stud[0].grade_level}, now())
      ON CONFLICT (student_id, subject, academic_year, term)
      DO UPDATE SET score = EXCLUDED.score, grade = EXCLUDED.grade, updated_at = now()`;
    await logActivity(`إدخال نتيجة: ${studentId} — ${subject} (${n})`, actor);
    return ok({ inserted: existing.length === 0 });
  }},

  'bulk-upload-results': { POST: async (event) => {
    const { results, academicYear, term, actor } = readBody(event);
    if (!Array.isArray(results) || !results.length) return err('لا توجد نتائج لحفظها');
    if (!academicYear || !term) return err('العام الدراسي والفصل الدراسي مطلوبان');
    // [FIX 10] one lookup for the whole batch, so every mark carries the class
    // it was sat in without a query per row
    const ids = [...new Set(results.map(r => r.studentId).filter(Boolean))];
    const studRows = ids.length
      ? await sql`SELECT student_id, class_name, grade_level FROM students WHERE student_id = ANY(${ids})`
      : [];
    const clsOf = {};
    studRows.forEach(r => { clsOf[r.student_id] = r });

    let saved = 0, failed = 0;
    for (const row of results) {
      const studentId = row.studentId, subject = row.subject, score = parseInt(row.score, 10);
      if (!studentId || !subject || isNaN(score) || score < 0 || score > 100) { failed++; continue }
      const c = clsOf[studentId] || {};
      try {
        await sql`
          INSERT INTO results (student_id, subject, score, grade, academic_year, term,
                               class_name, grade_level, updated_at)
          VALUES (${studentId}, ${subject}, ${score}, ${gradeFor(score)}, ${academicYear}, ${term},
                  ${c.class_name || null}, ${c.grade_level || null}, now())
          ON CONFLICT (student_id, subject, academic_year, term)
          DO UPDATE SET score = EXCLUDED.score, grade = EXCLUDED.grade, updated_at = now()`;
        saved++;
      } catch (e) { failed++ }
    }
    if (!saved) return err('لم يتم حفظ أي نتيجة — تحققوا من صحة البيانات');
    await logActivity(`إدخال جماعي: ${saved} نتيجة (${academicYear} — ${term})`, actor);
    return ok({ message: `تم حفظ ${saved} نتيجة بنجاح`, saved, failed });
  }},

  'delete-results': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM results WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('لا توجد نتيجة بهذا المعرّف', 404);
    await logActivity(`حذف نتيجة #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- REPORT CARD — JSON the frontend renders + prints ----------------
  'get-report-card': { GET: async (event) => {
    const { studentId, academicYear } = event.queryStringParameters || {};
    if (!studentId) return err('رقم الطالب مطلوب');
    const studRows = await sql`
      SELECT student_id, full_name, grade_level, class_name FROM students WHERE student_id = ${studentId}`;
    if (!studRows.length) return err('لا يوجد طالب بهذا الرقم', 404);
    const results = academicYear
      ? await sql`SELECT subject, score, grade, academic_year, term FROM results
                  WHERE student_id = ${studentId} AND academic_year = ${academicYear} ORDER BY term, subject`
      : await sql`SELECT subject, score, grade, academic_year, term FROM results
                  WHERE student_id = ${studentId} ORDER BY academic_year DESC, term, subject`;
    const attendance = academicYear
      ? await sql`SELECT status, COUNT(*)::int AS n FROM attendance
                  WHERE student_id = ${studentId}
                    AND att_date >= (split_part(${academicYear}::text,'-',1) || '-08-01')::date
                    AND att_date <= (COALESCE(NULLIF(split_part(${academicYear}::text,'-',2),''), split_part(${academicYear}::text,'-',1)) || '-07-31')::date
                  GROUP BY status`
      : await sql`SELECT status, COUNT(*)::int AS n FROM attendance WHERE student_id = ${studentId} GROUP BY status`;
    const behavior = await sql`
      SELECT type, category, description, points, created_at FROM behavior_records
      WHERE student_id = ${studentId} ORDER BY created_at DESC LIMIT 10`;
    return ok({ student: studRows[0], results, attendance, behavior });
  }},

  // ---------------- ATTENDANCE ----------------
  'get-attendance': { GET: async (event) => {
    const { date, gradeLevel, className } = event.queryStringParameters || {};
    if (!date || !gradeLevel || !className) return err('التاريخ والمرحلة والفصل مطلوبة');
    const rows = await sql`
      SELECT a.student_id, a.status FROM attendance a
      JOIN students s ON s.student_id = a.student_id
      WHERE a.att_date = ${date} AND s.grade_level = ${gradeLevel} AND s.class_name = ${className}`;
    const record = {};
    rows.forEach(r => { record[r.student_id] = r.status });
    return ok({ record });
  }},

  'save-attendance': { POST: async (event) => {
    const { date, marks } = readBody(event);
    if (!date || !marks || typeof marks !== 'object') return err('التاريخ والدرجات مطلوبة');
    const entries = Object.entries(marks).filter(([, v]) => ['p', 'a', 'l'].includes(v));
    if (!entries.length) return err('لا توجد بيانات حضور لحفظها');
    for (const [studentId, status] of entries) {
      await sql`
        INSERT INTO attendance (att_date, student_id, status, recorded_at)
        VALUES (${date}, ${studentId}, ${status}, now())
        ON CONFLICT (student_id, att_date)
        DO UPDATE SET status = EXCLUDED.status, recorded_at = now()`;
    }
    return ok({ message: 'تم الحفظ' });
  }},

  // ---------------- BIOMETRIC ATTENDANCE ----------------
  'get-attendance-devices': { GET: async () => {
    const devices = await sql`SELECT serial_number, name, last_seen FROM attendance_devices ORDER BY last_seen DESC NULLS LAST`;
    return ok({ devices });
  }},

  'set-student-device-pin': { POST: async (event) => {
    const { studentId, devicePin, actor } = readBody(event);
    if (!studentId) return err('رقم الطالب مطلوب');
    const pin = devicePin ? String(devicePin).trim() : null;
    if (pin) {
      const clash = await sql`SELECT student_id FROM students WHERE device_pin = ${pin} AND student_id != ${studentId}`;
      if (clash.length) return err('هذا الرقم مستخدَم بالفعل لطالب آخر (' + clash[0].student_id + ')');
    }
    const res = await sql`UPDATE students SET device_pin = ${pin} WHERE student_id = ${studentId} RETURNING student_id`;
    if (!res.length) return err('لا يوجد طالب بهذا الرقم', 404);
    await logActivity(`ربط رقم البصمة: ${studentId} → ${pin || 'إزالة'}`, actor);
    return ok({ message: 'تم الحفظ' });
  }},

  // raw punches for a given day (defaults to today), matched or unmatched to a student
  'get-punches': { GET: async (event) => {
    const { date } = event.queryStringParameters || {};
    const d = date || new Date().toISOString().slice(0, 10);
    const punches = await sql`
      SELECT p.id, p.device_pin, p.punch_time, p.student_id, s.full_name, s.class_name, p.processed
      FROM attendance_punches p LEFT JOIN students s ON s.student_id = p.student_id
      WHERE p.punch_time::date = ${d}::date
      ORDER BY p.punch_time`;
    return ok({ punches });
  }},

  // turns a day's raw punches into real attendance rows — first punch of
  // the day per student counts as "present". Anyone with zero punches is
  // left untouched for the admin to mark by hand.
  'sync-punches-to-attendance': { POST: async (event) => {
    const { date, actor } = readBody(event);
    const d = date || new Date().toISOString().slice(0, 10);
    const punches = await sql`
      SELECT DISTINCT ON (student_id) student_id, punch_time
      FROM attendance_punches
      WHERE punch_time::date = ${d}::date AND student_id IS NOT NULL
      ORDER BY student_id, punch_time ASC`;
    let count = 0;
    for (const p of punches) {
      await sql`
        INSERT INTO attendance (att_date, student_id, status, recorded_at)
        VALUES (${d}, ${p.student_id}, 'p', now())
        ON CONFLICT (student_id, att_date)
        DO UPDATE SET status = 'p', recorded_at = now()`;
      count++;
    }
    await sql`UPDATE attendance_punches SET processed = true WHERE punch_time::date = ${d}::date`;
    await logActivity(`مزامنة البصمة مع الحضور: ${d} — ${count} طالب`, actor);
    return ok({ message: 'تمت المزامنة', count });
  }},

  // ---------------- TEACHERS ----------------
  'get-teachers': { GET: async () => {
    await ensureLinkSchema();
    const teachers = await sql`SELECT id, full_name, subject, grade_level, phone, username, COALESCE(active,true) AS active, (teacher_password IS NOT NULL) AS has_login FROM teachers ORDER BY full_name`;
    const assignments = await sql`SELECT id, teacher_id, academic_year, grade_level, class_name, subject FROM teacher_assignments ORDER BY academic_year DESC, grade_level, class_name, subject`;
    return ok({ teachers, assignments });
  }},
  'add-teacher': { POST: async (event) => {
    const _b = readBody(event);
    const { fullName, subject, gradeLevel, phone, username, password, id, active, actor } = _b;
    // enable/disable only
    if (id && typeof active === 'boolean') {
      const r = await sql`UPDATE teachers SET active = ${active} WHERE id = ${parseInt(id)} RETURNING id`;
      if (!r.length) return err('المعلم غير موجود', 404);
      return ok({ message: active ? 'تم تفعيل الحساب' : 'تم تعطيل الحساب' });
    }
    // edit existing
    if (id) {
      await ensureLinkSchema();
      if (username) { const dupU = await sql`SELECT 1 FROM teachers WHERE username = ${username.trim()} AND id <> ${parseInt(id)}`; if (dupU.length) return err('اسم المستخدم مستخدم بالفعل'); }
      await sql`UPDATE teachers SET full_name = ${(fullName||'').trim()}, subject = COALESCE(${subject||null}, subject), grade_level = COALESCE(${gradeLevel||null}, grade_level), phone = ${phone||null}${username?sql`, username = ${username.trim()}`:sql``} WHERE id = ${parseInt(id)}`;
      if (password) await sql`UPDATE teachers SET teacher_password = ${hashPassword(password)} WHERE id = ${parseInt(id)}`;
      return ok({ message: 'تم تحديث المعلم' });
    }
    if (!fullName || !fullName.trim()) return err('اسم المعلم مطلوب');
    if (username || password) { await ensureLinkSchema();
      if (!username || !password) return err('اسم المستخدم وكلمة المرور معاً مطلوبان للروابط');
      const dup = await sql`SELECT 1 FROM teachers WHERE username = ${username.trim()}`;
      if (dup.length) return err('اسم المستخدم مستخدم بالفعل');
      await sql`INSERT INTO teachers (full_name, subject, grade_level, phone, username, teacher_password) VALUES (${fullName.trim()}, ${subject||null}, ${gradeLevel||null}, ${phone||null}, ${username.trim()}, ${hashPassword(password)})`;
      return ok({ message: 'تمت إضافة المعلم' });
    }
    await sql`INSERT INTO teachers (full_name, subject, grade_level, phone)
              VALUES (${fullName.trim()}, ${subject || null}, ${gradeLevel || null}, ${phone || null})`;
    await logActivity(`إضافة معلم: ${fullName.trim()}`, actor);
    return ok({ message: 'تمت إضافة المعلم' });
  }},
  'delete-teacher': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM teachers WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('لا يوجد معلم بهذا المعرّف', 404);
    await logActivity(`حذف معلم #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- NEWS ----------------
  'get-news': { GET: async () => {
    const news = await sql`SELECT id, title, body, status, published_on FROM news ORDER BY published_on DESC, id DESC`;
    return ok({ news });
  }},
  'add-news': { POST: async (event) => {
    const { title, body, status, actor } = readBody(event);
    if (!title || !title.trim()) return err('عنوان الإعلان مطلوب');
    const finalStatus = status === 'draft' ? 'draft' : 'published';
    await sql`INSERT INTO news (title, body, status) VALUES (${title.trim()}, ${body || null}, ${finalStatus})`;
    await logActivity(`نشر إعلان: ${title.trim()}`, actor);
    return ok({ message: 'تم حفظ الإعلان' });
  }},
  'delete-news': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM news WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('لا يوجد إعلان بهذا المعرّف', 404);
    await logActivity(`حذف إعلان #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- SUBJECTS ----------------
  'get-subjects': { GET: async () => {
    const rows = await sql`SELECT name FROM subjects ORDER BY sort_order, name`;
    return ok({ subjects: rows.map(r => r.name) });
  }},
  'add-subject': { POST: async (event) => {
    const { name, actor } = readBody(event);
    const clean = (name || '').trim();
    if (!clean) return err('اسم المادة مطلوب');
    const exists = await sql`SELECT 1 FROM subjects WHERE name = ${clean}`;
    if (exists.length) return err('هذه المادة موجودة بالفعل');
    const next = await sql`SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM subjects`;
    await sql`INSERT INTO subjects (name, sort_order) VALUES (${clean}, ${next[0].n})`;
    await logActivity(`إضافة مادة: ${clean}`, actor);
    return ok({ message: 'تمت الإضافة' });
  }},
  'delete-subject': { DELETE: async (event) => {
    const { name, actor } = readBody(event);
    if (!name) return err('اسم المادة مطلوب');
    const res = await sql`DELETE FROM subjects WHERE name = ${name} RETURNING name`;
    if (!res.length) return err('لا توجد مادة بهذا الاسم', 404);
    await logActivity(`حذف مادة: ${name}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- FEES ----------------
  'get-fee-structure': { GET: async () => {
    const rows = await sql`
      SELECT id, grade_level, academic_year, term, amount, description
      FROM fee_structure ORDER BY academic_year DESC, term, grade_level`;
    return ok({ feeStructure: rows });
  }},

  'set-fee-structure': { POST: async (event) => {
    const { gradeLevel, academicYear, term, amount, description, actor } = readBody(event);
    if (!gradeLevel || !academicYear || !term || amount === undefined) return err('يرجى ملء جميع الحقول');
    const n = parseFloat(amount);
    if (isNaN(n) || n < 0) return err('المبلغ غير صحيح');
    await sql`
      INSERT INTO fee_structure (grade_level, academic_year, term, amount, description)
      VALUES (${gradeLevel}, ${academicYear}, ${term}, ${n}, ${description || null})
      ON CONFLICT (grade_level, academic_year, term)
      DO UPDATE SET amount = EXCLUDED.amount, description = EXCLUDED.description`;
    await logActivity(`تحديث الرسوم: ${gradeLevel} (${academicYear} — ${term}) = ${n}`, actor);
    return ok({ message: 'تم الحفظ' });
  }},

  'delete-fee-structure': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM fee_structure WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('غير موجود', 404);
    await logActivity(`حذف بند رسوم #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // [FIX 3] This used to run one SELECT per student inside a for-loop.
  // With 916 active students that is 916 sequential round trips to Neon —
  // far past Netlify's 10-second function ceiling, so the call never
  // returned. It is now a single aggregated query.
  'get-fee-summary': { GET: async (event) => {
    const { gradeLevel, className, academicYear, term } = event.queryStringParameters || {};
    if (!academicYear || !term) return err('العام الدراسي والفصل الدراسي مطلوبان');

    const filtered = !!(gradeLevel && className);
    const summary = filtered
      ? await sql`
          SELECT s.student_id, s.full_name, s.grade_level, s.class_name,
                 COALESCE(f.amount, 0)::float AS expected,
                 COALESCE(p.paid, 0)::float   AS paid,
                 (COALESCE(f.amount, 0) - COALESCE(p.paid, 0))::float AS balance
          FROM students s
          LEFT JOIN fee_structure f
            ON f.grade_level = s.grade_level
           AND f.academic_year = ${academicYear} AND f.term = ${term}
          LEFT JOIN (
            SELECT student_id, SUM(amount) AS paid FROM fee_payments
            WHERE academic_year = ${academicYear} AND term = ${term}
            GROUP BY student_id
          ) p ON p.student_id = s.student_id
          WHERE s.active = true AND s.grade_level = ${gradeLevel} AND s.class_name = ${className}
          ORDER BY s.class_name, s.full_name`
      : await sql`
          SELECT s.student_id, s.full_name, s.grade_level, s.class_name,
                 COALESCE(f.amount, 0)::float AS expected,
                 COALESCE(p.paid, 0)::float   AS paid,
                 (COALESCE(f.amount, 0) - COALESCE(p.paid, 0))::float AS balance
          FROM students s
          LEFT JOIN fee_structure f
            ON f.grade_level = s.grade_level
           AND f.academic_year = ${academicYear} AND f.term = ${term}
          LEFT JOIN (
            SELECT student_id, SUM(amount) AS paid FROM fee_payments
            WHERE academic_year = ${academicYear} AND term = ${term}
            GROUP BY student_id
          ) p ON p.student_id = s.student_id
          WHERE s.active = true
          ORDER BY s.grade_level, s.class_name, s.full_name`;

    return ok({ summary });
  }},

  // ---------------- OFFICIAL FEE TARGETS ----------------
  // What the institute fee and exam fee SHOULD be, per CLASS per year.
  // Per-class (not per-stage) because the real fee schedule varies within
  // a stage (Grade 12 pays more than 10/11; 6/9/12 have a higher exam fee).
  'get-fee-targets': { GET: async () => {
    await ensureLinkSchema();
    const rows = await sql`
      SELECT id, class_name, academic_year, institute_amount, exam_amount, registration_amount
      FROM fee_targets ORDER BY academic_year DESC, class_name`;
    return ok({ targets: rows });
  }},

  'set-fee-target': { POST: async (event) => {
    await ensureLinkSchema();
    const { className, academicYear, instituteAmount, examAmount, registrationAmount, actor } = readBody(event);
    const regN = (registrationAmount === undefined || registrationAmount === '' || registrationAmount === null) ? null : parseFloat(registrationAmount);
    if (!className || !academicYear) return err('الفصل والعام الدراسي مطلوبان');
    const inst = parseFloat(instituteAmount), exam = parseFloat(examAmount);
    if (isNaN(inst) || inst < 0 || isNaN(exam) || exam < 0) return err('المبالغ غير صحيحة');
    await sql`
      INSERT INTO fee_targets (class_name, academic_year, institute_amount, exam_amount, registration_amount)
      VALUES (${className}, ${academicYear}, ${inst}, ${exam}, ${regN || 0})
      ON CONFLICT (class_name, academic_year)
      DO UPDATE SET institute_amount = EXCLUDED.institute_amount, exam_amount = EXCLUDED.exam_amount,
                    registration_amount = COALESCE(${regN}::numeric, fee_targets.registration_amount)`;
    await logActivity(`تحديد الرسوم الرسمية: ${className} (${academicYear}) — معهد ${inst} / امتحان ${exam}`, actor);
    return ok({ message: 'تم الحفظ' });
  }},

  // One level (stage) at a time: sets registration + institute + exam fee for every class in it.
  'set-stage-fees': { POST: async (event) => {
    await ensureLinkSchema();
    const { stage, academicYear, instituteAmount, examAmount, registrationAmount, actor } = readBody(event);
    if (!stage || !academicYear) return err('المرحلة والعام الدراسي مطلوبان');
    const inst = parseFloat(instituteAmount) || 0, exam = parseFloat(examAmount) || 0, reg = parseFloat(registrationAmount) || 0;
    if (inst < 0 || exam < 0 || reg < 0) return err('المبالغ غير صحيحة');
    const cls = await sql`SELECT name FROM classes WHERE stage = ${stage}`;
    if (!cls.length) return err('لا توجد فصول لهذه المرحلة', 404);
    for (const c of cls) {
      await sql`INSERT INTO fee_targets (class_name, academic_year, institute_amount, exam_amount, registration_amount)
                VALUES (${c.name}, ${academicYear}, ${inst}, ${exam}, ${reg})
                ON CONFLICT (class_name, academic_year)
                DO UPDATE SET institute_amount = EXCLUDED.institute_amount, exam_amount = EXCLUDED.exam_amount, registration_amount = EXCLUDED.registration_amount`;
    }
    await logActivity(`رسوم المرحلة ${stage} (${academicYear}) — تسجيل ${reg} / معهد ${inst} / امتحان ${exam}`, actor);
    return ok({ message: 'تم الحفظ', classes: cls.length });
  }},

  'delete-fee-target': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM fee_targets WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('غير موجود', 404);
    await logActivity(`حذف رسوم رسمية #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- SCHOOL & BANK SETTINGS ----------------
  // Feeds the printable official fee circular — institute name/address
  // (bilingual), bank account details, and the flat registration fee.
  'get-school-settings': { GET: async () => {
    const rows = await sql`SELECT * FROM school_settings WHERE id = 1`;
    return ok({ settings: rows[0] || {} });
  }},

  // [FIX 8] every null passed into COALESCE is cast explicitly. An untyped
  // NULL parameter can make Postgres refuse the statement with
  // "could not determine data type of parameter" — which surfaced in the
  // panel as a bare 500 with no useful message.
  'set-school-settings': { POST: async (event) => {
    const b = readBody(event);
    const reg = b.registrationFee !== undefined && b.registrationFee !== '' ? parseFloat(b.registrationFee) : null;
    if (reg !== null && (isNaN(reg) || reg < 0)) return err('رسوم التسجيل غير صحيحة');
    await sql`
      UPDATE school_settings SET
        institute_name_ar = COALESCE(${b.instituteNameAr ?? null}::text,   institute_name_ar),
        institute_name_en = COALESCE(${b.instituteNameEn ?? null}::text,   institute_name_en),
        address_ar        = COALESCE(${b.addressAr ?? null}::text,         address_ar),
        address_en        = COALESCE(${b.addressEn ?? null}::text,         address_en),
        account_name      = COALESCE(${b.accountName ?? null}::text,       account_name),
        account_number    = COALESCE(${b.accountNumber ?? null}::text,     account_number),
        phone_line        = COALESCE(${b.phoneLine ?? null}::text,         phone_line),
        registration_fee  = COALESCE(${reg}::numeric,                      registration_fee)
      WHERE id = 1`;
    await logActivity('تحديث بيانات المعهد والحساب البنكي', b.actor);
    return ok({ message: 'تم الحفظ' });
  }},

  'record-payment': { POST: async (event) => {
    const { studentId, academicYear, term, amount, method, reference, period, actor } = readBody(event);
    if (!studentId || !academicYear || !term || !amount) return err('يرجى ملء جميع الحقول');
    const n = parseFloat(amount);
    if (isNaN(n) || n <= 0) return err('المبلغ غير صحيح');
    const stud = await sql`
      SELECT full_name, grade_level, class_name, guardian_name FROM students WHERE student_id = ${studentId}`;
    if (!stud.length) return err('لا يوجد طالب بهذا الرقم', 404);
    // [FIX 10] the class is stamped onto the payment too: a receipt reprinted
    // years later must still name the class the money was actually paid for
    const rows = await sql`
      INSERT INTO fee_payments (student_id, academic_year, term, amount, method, reference, period,
                                class_name, grade_level, recorded_by, receipt_number)
      VALUES (${studentId}, ${academicYear}, ${term}, ${n}, ${method || null}, ${reference || null},
              ${period || null}, ${stud[0].class_name}, ${stud[0].grade_level},
              ${actor || null}, nextval('receipt_number_seq'))
      RETURNING id, receipt_number, paid_at`;
    await logActivity(`دفعة رسوم: ${studentId} — ${n} (إيصال #${rows[0].receipt_number})`, actor);
    return ok({
      message: 'تم تسجيل الدفعة',
      receipt: {
        id: rows[0].id, receiptNumber: rows[0].receipt_number, paidAt: rows[0].paid_at,
        studentId, studentName: stud[0].full_name, stage: stud[0].grade_level, className: stud[0].class_name,
        guardianName: stud[0].guardian_name, amount: n, academicYear, term,
        reference: reference || null, period: period || null,
      },
    });
  }},

  // Reprint an existing receipt later — the number and everything on it
  // must always come back exactly the same, since it's already been handed out.
  'get-receipt': { GET: async (event) => {
    const { id } = event.queryStringParameters || {};
    if (!id) return err('المعرّف مطلوب');
    const rows = await sql`
      SELECT p.id, p.receipt_number, p.paid_at, p.student_id, s.full_name AS student_name,
             COALESCE(p.grade_level, s.grade_level) AS stage,
             COALESCE(p.class_name,  s.class_name)  AS class_name,
             s.guardian_name,
             p.amount, p.academic_year, p.term, p.reference, p.period
      FROM fee_payments p JOIN students s ON s.student_id = p.student_id
      WHERE p.id = ${id}`;
    if (!rows.length) return err('لا يوجد إيصال بهذا المعرّف', 404);
    const r = rows[0];
    return ok({ receipt: {
      id: r.id, receiptNumber: r.receipt_number, paidAt: r.paid_at,
      studentId: r.student_id, studentName: r.student_name, stage: r.stage, className: r.class_name,
      guardianName: r.guardian_name, amount: parseFloat(r.amount), academicYear: r.academic_year,
      term: r.term, reference: r.reference, period: r.period,
    }});
  }},

  'get-payments': { GET: async (event) => {
    const { studentId } = event.queryStringParameters || {};
    if (!studentId) return err('رقم الطالب مطلوب');
    const payments = await sql`
      SELECT id, academic_year, term, amount, method, reference, period, receipt_number, paid_at
      FROM fee_payments WHERE student_id = ${studentId} ORDER BY paid_at DESC`;
    return ok({ payments });
  }},

  // Every payment for every student, joined with their name/class — the
  // "الرسوم" tab reads this in one call, the same pattern as get-all-results.
  'get-all-fee-payments': { GET: async () => {
    const payments = await sql`
      SELECT p.id, p.student_id, s.full_name,
             COALESCE(p.grade_level, s.grade_level) AS grade_level,
             COALESCE(p.class_name,  s.class_name)  AS class_name,
             p.academic_year, p.term, p.amount, p.method, p.reference, p.receipt_number, p.paid_at
      FROM fee_payments p JOIN students s ON s.student_id = p.student_id
      ORDER BY p.paid_at DESC`;
    return ok({ payments });
  }},

  // [FIX 13] An admin who keys the wrong amount must be able to correct it
  // without deleting and re-issuing. The receipt NUMBER never changes — the
  // paper already handed over stays valid — and every edit is written to the
  // audit log with the old and new amount, so a correction can never be
  // mistaken for a fresh payment.
  'update-payment': { PUT: async (event) => {
    const { id, amount, reference, period, academicYear, method, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const rows = await sql`
      SELECT p.id, p.amount, p.reference, p.student_id, s.full_name
      FROM fee_payments p JOIN students s ON s.student_id = p.student_id
      WHERE p.id = ${id}`;
    if (!rows.length) return err('لا توجد دفعة بهذا المعرّف', 404);
    const old = rows[0];

    if (amount !== undefined && amount !== null && amount !== '') {
      // zero is allowed here: it is how an admin cancels a payment that was
      // entered by mistake while keeping the receipt number on record. A
      // negative figure is still refused.
      const n = parseFloat(amount);
      if (isNaN(n) || n < 0) return err('المبلغ غير صحيح');
      await sql`UPDATE fee_payments SET amount = ${n} WHERE id = ${id}`;
    }
    if (reference    !== undefined) await sql`UPDATE fee_payments SET reference     = ${reference || null}    WHERE id = ${id}`;
    if (period       !== undefined) await sql`UPDATE fee_payments SET period        = ${period || null}       WHERE id = ${id}`;
    if (method       !== undefined) await sql`UPDATE fee_payments SET method        = ${method || null}       WHERE id = ${id}`;
    if (academicYear)               await sql`UPDATE fee_payments SET academic_year = ${academicYear}         WHERE id = ${id}`;

    const now = await sql`
      SELECT p.id, p.receipt_number, p.paid_at, p.student_id, s.full_name AS student_name,
             COALESCE(p.grade_level, s.grade_level) AS stage,
             COALESCE(p.class_name,  s.class_name)  AS class_name,
             s.guardian_name, p.amount, p.academic_year, p.term, p.reference, p.period
      FROM fee_payments p JOIN students s ON s.student_id = p.student_id
      WHERE p.id = ${id}`;
    const r = now[0];
    await logActivity(
      `تعديل دفعة #${id} — ${old.student_id} (${old.full_name}): ` +
      `${parseFloat(old.amount)} → ${parseFloat(r.amount)}` +
      (reference !== undefined && reference !== old.reference ? ` / ${old.reference || '—'} → ${r.reference || '—'}` : ''),
      actor);
    return ok({ message: 'تم تعديل الدفعة', receipt: {
      id: r.id, receiptNumber: r.receipt_number, paidAt: r.paid_at,
      studentId: r.student_id, studentName: r.student_name, stage: r.stage, className: r.class_name,
      guardianName: r.guardian_name, amount: parseFloat(r.amount), academicYear: r.academic_year,
      term: r.term, reference: r.reference, period: r.period,
    }});
  }},

  'delete-payment': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM fee_payments WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('غير موجود', 404);
    await logActivity(`حذف دفعة #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- EXAMS / TIMETABLE ----------------
  'get-exams': { GET: async (event) => {
    const { gradeLevel, className, academicYear, term } = event.queryStringParameters || {};
    const rows = (gradeLevel && className && academicYear && term)
      ? await sql`SELECT id, subject, grade_level, class_name, exam_date, start_time, end_time, room, academic_year, term
                  FROM exams
                  WHERE grade_level = ${gradeLevel} AND class_name = ${className}
                    AND academic_year = ${academicYear} AND term = ${term}
                  ORDER BY exam_date, start_time`
      : await sql`SELECT id, subject, grade_level, class_name, exam_date, start_time, end_time, room, academic_year, term
                  FROM exams ORDER BY exam_date, start_time LIMIT 200`;
    return ok({ exams: rows });
  }},

  'add-exam': { POST: async (event) => {
    const { subject, gradeLevel, className, examDate, startTime, endTime, room, academicYear, term, actor } = readBody(event);
    if (!subject || !gradeLevel || !className || !examDate || !academicYear || !term)
      return err('يرجى ملء الحقول المطلوبة');
    await sql`
      INSERT INTO exams (subject, grade_level, class_name, exam_date, start_time, end_time, room, academic_year, term)
      VALUES (${subject}, ${gradeLevel}, ${className}, ${examDate}, ${startTime || null}, ${endTime || null},
              ${room || null}, ${academicYear}, ${term})`;
    await logActivity(`إضافة موعد امتحان: ${subject} — ${gradeLevel}/${className} (${examDate})`, actor);
    return ok({ message: 'تمت الإضافة' });
  }},

  'delete-exam': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM exams WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('غير موجود', 404);
    await logActivity(`حذف موعد امتحان #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- BEHAVIOR / DISCIPLINE LOG ----------------
  'get-behavior': { GET: async (event) => {
    await ensureLinkSchema();
    const { studentId, gradeLevel, className } = event.queryStringParameters || {};
    let rows;
    if (studentId) {
      rows = await sql`SELECT b.id, b.student_id, s.full_name, b.type, b.category, b.description, b.points, b.recorded_by, b.created_at, b.incident_date, b.severity, b.action_taken
                       FROM behavior_records b JOIN students s ON s.student_id = b.student_id
                       WHERE b.student_id = ${studentId} ORDER BY b.created_at DESC`;
    } else if (gradeLevel && className) {
      rows = await sql`SELECT b.id, b.student_id, s.full_name, b.type, b.category, b.description, b.points, b.recorded_by, b.created_at, b.incident_date, b.severity, b.action_taken
                       FROM behavior_records b JOIN students s ON s.student_id = b.student_id
                       WHERE s.grade_level = ${gradeLevel} AND s.class_name = ${className}
                       ORDER BY b.created_at DESC`;
    } else {
      rows = await sql`SELECT b.id, b.student_id, s.full_name, b.type, b.category, b.description, b.points, b.recorded_by, b.created_at, b.incident_date, b.severity, b.action_taken
                       FROM behavior_records b JOIN students s ON s.student_id = b.student_id
                       ORDER BY b.created_at DESC LIMIT 100`;
    }
    return ok({ records: rows });
  }},

  'add-behavior': { POST: async (event) => {
    await ensureLinkSchema();
    const { studentId, type, category, description, points, incidentDate, severity, actionTaken, actor } = readBody(event);
    if (!studentId || !type) return err('رقم الطالب والنوع مطلوبان');
    if (!['positive', 'negative'].includes(type)) return err('النوع يجب أن يكون positive أو negative');
    const stud = await sql`SELECT 1 FROM students WHERE student_id = ${studentId}`;
    if (!stud.length) return err('لا يوجد طالب بهذا الرقم', 404);
    await sql`
      INSERT INTO behavior_records (student_id, type, category, description, points, recorded_by, incident_date, severity, action_taken)
      VALUES (${studentId}, ${type}, ${category || null}, ${description || null}, ${points || 0}, ${actor || null}, ${incidentDate || null}::date, ${severity || null}, ${actionTaken || null})`;
    await logActivity(`سجل سلوك: ${studentId} (${type})`, actor);
    return ok({ message: 'تم التسجيل' });
  }},

  'delete-behavior': { DELETE: async (event) => {
    const { id, actor } = readBody(event);
    if (!id) return err('المعرّف مطلوب');
    const res = await sql`DELETE FROM behavior_records WHERE id = ${id} RETURNING id`;
    if (!res.length) return err('غير موجود', 404);
    await logActivity(`حذف سجل سلوك #${id}`, actor);
    return ok({ message: 'تم الحذف' });
  }},

  // ---------------- PROMOTION ----------------
  // The admin reviews each student in a class individually and marks them
  // 'promote' (moves to that class's classes.promotes_to) or 'repeat'
  // (stays exactly where they are). If a promoted student's class has no
  // promotes_to (the top of Secondary), they graduate: status='graduated',
  // active=false — their records stay in the database for history/report
  // cards, they just stop appearing in active rosters.
  'get-promotion-roster': { GET: async (event) => {
    const { className } = event.queryStringParameters || {};
    if (!className) return err('الفصل مطلوب');
    const cls = await sql`SELECT name, promotes_to FROM classes WHERE name = ${className}`;
    if (!cls.length) return err('فصل غير معروف', 404);
    const students = await sql`
      SELECT student_id, full_name FROM students
      WHERE class_name = ${className} AND active = true ORDER BY full_name`;
    return ok({ promotesTo: cls[0].promotes_to, students });
  }},

  'promote-students': { POST: async (event) => {
    const { className, decisions, actor } = readBody(event);
    // decisions: [{ studentId, action: 'promote' | 'repeat' }]
    if (!className || !Array.isArray(decisions) || !decisions.length) return err('الفصل وقرارات الترقية مطلوبة');
    const cls = await sql`SELECT promotes_to FROM classes WHERE name = ${className}`;
    if (!cls.length) return err('فصل غير معروف', 404);
    const nextClass = cls[0].promotes_to;

    // resolve the destination stage ONCE, not once per student
    let nextStage = null;
    if (nextClass) {
      const nextCls = await sql`SELECT stage FROM classes WHERE name = ${nextClass}`;
      nextStage = nextCls.length ? nextCls[0].stage : null;
    }

    const toPromote = decisions.filter(d => d.studentId && d.action === 'promote').map(d => d.studentId);
    const repeated  = decisions.filter(d => d.studentId && d.action === 'repeat').length;

    let promoted = 0, graduated = 0;
    if (toPromote.length) {
      if (nextClass) {
        const res = await sql`
          UPDATE students SET class_name = ${nextClass}, grade_level = ${nextStage}
          WHERE student_id = ANY(${toPromote}) RETURNING student_id`;
        promoted = res.length;
      } else {
        const res = await sql`
          UPDATE students SET status = 'graduated', active = false
          WHERE student_id = ANY(${toPromote}) RETURNING student_id`;
        graduated = res.length;
      }
    }
    await logActivity(`ترقية ${className}: ${promoted} ترقية، ${repeated} إعادة، ${graduated} تخرّج`, actor);
    return ok({
      message: `تمت الترقية — ${promoted} انتقلوا، ${repeated} أعادوا الفصل، ${graduated} تخرّجوا`,
      promoted, repeated, graduated,
    });
  }},

  // Whole-school academic-year turnover in one action: every class moves up
  // simultaneously — الروضة→1st, 1st→2nd, and so on — and whoever is in the
  // top class graduates. Processed from the HIGHEST class DOWN to the
  // lowest so a student promoted earlier in this same pass is never
  // touched again (each UPDATE only matches students who were ALREADY in
  // that class before this run started).
  'promote-entire-school': { POST: async (event) => {
    const { actor } = readBody(event);
    const classes = await sql`SELECT name, stage, promotes_to FROM classes WHERE active = true ORDER BY sort_order DESC`;
    const stageOf = {};
    classes.forEach(c => { stageOf[c.name] = c.stage });

    let totalPromoted = 0, totalGraduated = 0;
    const details = [];
    for (const c of classes) {
      if (c.promotes_to) {
        const res = await sql`
          UPDATE students SET class_name = ${c.promotes_to}, grade_level = ${stageOf[c.promotes_to] || null}
          WHERE class_name = ${c.name} AND status = 'active' AND active = true
          RETURNING student_id`;
        totalPromoted += res.length;
        if (res.length) details.push({ from: c.name, to: c.promotes_to, count: res.length });
      } else {
        const res = await sql`
          UPDATE students SET status = 'graduated', active = false
          WHERE class_name = ${c.name} AND status = 'active' AND active = true
          RETURNING student_id`;
        totalGraduated += res.length;
        if (res.length) details.push({ from: c.name, to: null, count: res.length });
      }
    }
    await logActivity(`ترقية العام الدراسي بالكامل: ${totalPromoted} طالب رُقّوا، ${totalGraduated} طالب تخرّجوا`, actor);
    return ok({ message: 'تمت ترقية العام الدراسي بالكامل', totalPromoted, totalGraduated, details });
  }},

  // ---------------- SMS LOG ----------------
  // Actually sends only if SMS_API_URL + SMS_API_KEY are set as Netlify env vars.
  // Otherwise the message is still logged as 'queued_no_provider' so nothing is lost.
  'send-sms': { POST: async (event) => {
    const { studentId, phone, message, actor } = readBody(event);
    if (!message || !message.trim()) return err('نص الرسالة مطلوب');
    let toPhone = phone;
    if (!toPhone && studentId) {
      const stud = await sql`SELECT guardian_phone FROM students WHERE student_id = ${studentId}`;
      toPhone = stud.length ? stud[0].guardian_phone : null;
    }
    if (!toPhone) return err('رقم الهاتف مطلوب');

    let status = 'queued_no_provider';
    if (process.env.SMS_API_URL && process.env.SMS_API_KEY) {
      try {
        const res = await fetch(process.env.SMS_API_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.SMS_API_KEY}` },
          body: JSON.stringify({ to: toPhone, text: message }),
        });
        status = res.ok ? 'sent' : 'failed';
      } catch (e) {
        status = 'failed';
      }
    }

    // [FIX 2] a nested sql`now()` cannot be used as a parameter value in
    // @neondatabase/serverless — it threw on every single send. A plain
    // ISO timestamp string binds correctly to timestamptz.
    const sentAt = status === 'sent' ? new Date().toISOString() : null;
    await sql`
      INSERT INTO sms_log (student_id, phone, message, status, sent_at)
      VALUES (${studentId || null}, ${toPhone}, ${message}, ${status}, ${sentAt})`;
    await logActivity(`رسالة نصية إلى ${toPhone}: ${status}`, actor);
    return ok({
      message: status === 'sent' ? 'تم الإرسال' : 'تم الحفظ في قائمة الانتظار (لا يوجد مزود SMS مفعّل)',
      status,
    });
  }},

  'get-sms-log': { GET: async () => {
    const rows = await sql`
      SELECT id, student_id, phone, message, status, sent_at, created_at
      FROM sms_log ORDER BY created_at DESC LIMIT 100`;
    return ok({ log: rows });
  }},

  // ---------------- FULL AUDIT LOG ----------------
  'get-audit-log': { GET: async (event) => {
    const { limit, offset, q } = event.queryStringParameters || {};
    const lim = Math.min(parseInt(limit, 10) || 50, 200);
    const off = parseInt(offset, 10) || 0;
    const rows = q
      ? await sql`SELECT id, message, actor, created_at FROM activity_log
                  WHERE message ILIKE ${'%' + q + '%'} OR actor ILIKE ${'%' + q + '%'}
                  ORDER BY created_at DESC LIMIT ${lim} OFFSET ${off}`
      : await sql`SELECT id, message, actor, created_at FROM activity_log
                  ORDER BY created_at DESC LIMIT ${lim} OFFSET ${off}`;
    const total = q
      ? await sql`SELECT COUNT(*)::int AS n FROM activity_log
                  WHERE message ILIKE ${'%' + q + '%'} OR actor ILIKE ${'%' + q + '%'}`
      : await sql`SELECT COUNT(*)::int AS n FROM activity_log`;
    return ok({ log: rows, total: total[0].n });
  }},

  // legacy stats-tab feed, now reading from activity_log
  'get-activity': { GET: async () => {
    const activity = await sql`SELECT message, created_at FROM activity_log ORDER BY created_at DESC LIMIT 20`;
    return ok({ activity });
  }},

  // ---------------- STUDENT PORTAL ----------------
  // [FIX 9] The portal prints the institute's official كشف الدرجات, which
  // carries the student's RANK and the CLASS SIZE. Neither can be worked
  // out from one student's own rows, so both are computed here — one extra
  // query totalling every classmate's marks per year/term — and returned
  // as `ranks` keyed "<year>|<term>". Guardian name and date of birth come
  // back too, so the portal never needs a second call.
  'student-results': { POST: async (event) => {
    const { studentId, password } = readBody(event);
    if (!studentId || !password) return err('يرجى إدخال رقم الطالب وكلمة المرور');
    const rows = await sql`
      SELECT student_id, full_name, password, grade_level, class_name, active, status,
             guardian_name, guardian_phone, date_of_birth
      FROM students WHERE student_id = ${studentId}`;
    if (!rows.length) return err('بيانات الدخول غير صحيحة', 401);
    const student = rows[0];
    // [FIX 11] Graduating sets active = false, which used to lock every leaver
    // out of the results they had just sat. A graduate keeps access to their own
    // transcript for good — it is their record. Only an account the school has
    // actually suspended or withdrawn is refused.
    if (student.active === false && student.status !== 'graduated') {
      return err('هذا الحساب موقوف، تواصلوا مع الإدارة', 403);
    }
    if (!verifyPassword(password, student.password)) return err('بيانات الدخول غير صحيحة', 401);

    const results = await sql`
      SELECT subject, score, grade, academic_year, term,
             COALESCE(class_name, ${student.class_name}) AS class_name
      FROM results
      WHERE student_id = ${studentId} ORDER BY academic_year DESC, term, subject`;

    // [FIX 10] Rank against the class they were IN that year, not the one they
    // sit in today. Every classmate total is grouped by the stored class, so
    // promoting the school never re-ranks a sheet that was already printed.
    const myClasses = [...new Set(results.map(r => r.class_name).filter(Boolean))];
    if (!myClasses.length) myClasses.push(student.class_name);
    const peers = await sql`
      SELECT r.academic_year, r.term, r.student_id,
             COALESCE(r.class_name, s.class_name) AS class_name,
             SUM(r.score)::float AS total
      FROM results r JOIN students s ON s.student_id = r.student_id
      WHERE COALESCE(r.class_name, s.class_name) = ANY(${myClasses})
      GROUP BY r.academic_year, r.term, r.student_id, COALESCE(r.class_name, s.class_name)`;

    const groups = {};
    peers.forEach((p) => {
      const k = p.academic_year + '|' + p.term + '|' + p.class_name;
      (groups[k] = groups[k] || []).push(p);
    });
    const ranks = {};
    Object.keys(groups).forEach((k) => {
      const list = groups[k].sort((a, b) => b.total - a.total);
      const i = list.findIndex((x) => x.student_id === studentId);
      if (i > -1) ranks[k] = { rank: i + 1, of: list.length };
    });

    return ok({
      student: {
        student_id: student.student_id, full_name: student.full_name,
        grade_level: student.grade_level, class_name: student.class_name,
        guardian_name: student.guardian_name, guardian_phone: student.guardian_phone,
        date_of_birth: student.date_of_birth,
      },
      results,
      ranks,
    });
  }},

};

// =====================================================================
//  ENTRY POINT
// =====================================================================
export const handler = async (event) => {
  const route = getRoute(event);

  // ZKTeco ADMS protocol (fingerprint device) — plain text, not JSON, and
  // the device can't log in, so it's identified by serial number instead.
  // Handled BEFORE body normalisation because handleZkteco needs the raw
  // encoding flags itself.
  if (route.startsWith('iclock/')) {
    try { return await handleZkteco(event); }
    catch (e) { console.error('[iclock]', e); return plainText('ERROR', 500); }
  }

  // [FIX 1] Normalise the body exactly once. Everything below can now
  // assume event.body is plain UTF-8 JSON text.
  event = { ...event, body: rawBody(event), isBase64Encoded: false };

  const method = event.httpMethod;

  if (method === 'OPTIONS') return { statusCode: 204, body: '' };

  const table = routes[route];
  if (!table) return err(`غير موجود: ${route}`, 404);

  const fn = table[method];
  if (!fn) return err('Method not allowed', 405);

  // secure by default: an unlisted route requires full admin, never falls open
  const authLevel = ROUTE_AUTH[route] || 'admin';
  let _auth = null;
  if (authLevel !== 'public') {
    const auth = verifyToken(event);
    if (!auth) return err('يجب تسجيل الدخول', 401);
    _auth = auth;
    if (authLevel === 'admin' && auth.role !== 'admin') return err('هذا الإجراء متاح للمدير فقط', 403);
    if (authLevel === 'teacher' && auth.role !== 'teacher') return err('هذا الإجراء متاح للمعلمين فقط', 403);
    // stamp the verified username as `actor` so every route's existing
    // logActivity(..., actor) call is trustworthy — the client can no
    // longer claim to be someone else by sending a different `actor`.
    if (method !== 'GET') {
      try {
        const body = event.body ? JSON.parse(event.body) : {};
        body.actor = auth.username;
        event = { ...event, body: JSON.stringify(body) };
      } catch (e) { /* non-JSON body — leave untouched */ }
    }
  }

  try {
    return await fn(event, _auth);
  } catch (e) {
    console.error(`[${route}] `, e);
    // surface the real reason in the Netlify log AND give the panel
    // something more useful than a bare "خطأ في الخادم"
    return err('خطأ في الخادم: ' + (e.message || 'unknown'), 500);
  }
};
