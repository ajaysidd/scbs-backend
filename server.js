require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 4000;

// ── DB ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDB() {
  const c = await pool.connect();
  try {
    await c.query(`CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      full_name VARCHAR(255) NOT NULL,
      password_hash VARCHAR(255),
      role VARCHAR(20) DEFAULT 'user',
      verified BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS files (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      original_name VARCHAR(500) NOT NULL,
      encrypted_data TEXT NOT NULL,
      iv VARCHAR(255) NOT NULL,
      algorithm VARCHAR(50) DEFAULT 'AES-GCM',
      size BIGINT NOT NULL,
      shared BOOLEAN DEFAULT false,
      uploaded_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS file_shares (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      file_id UUID REFERENCES files(id) ON DELETE CASCADE,
      owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
      shared_with_id UUID REFERENCES users(id) ON DELETE CASCADE,
      message TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(file_id, shared_with_id)
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID,
      action VARCHAR(100) NOT NULL,
      detail VARCHAR(500),
      ip VARCHAR(100),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    console.log('DB ready');
  } finally { c.release(); }
}

// ── MIDDLEWARE ──
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 30 }));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function token(user) {
  return jwt.sign({ userId: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function safe(u) {
  const { password_hash, ...rest } = u;
  return rest;
}

// ── HEALTH ──
app.get('/health', (req, res) => res.json({ status: 'OK', version: '1.0.0', time: new Date().toISOString() }));

// ── AUTH ROUTES ──
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, fullName } = req.body;
    if (!email || !password || !fullName) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password min 8 characters' });
    const ex = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (ex.rows.length) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (email,full_name,password_hash) VALUES ($1,$2,$3)', [email.toLowerCase(), fullName, hash]);
    res.status(201).json({ message: 'Account created. You can now log in.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    await pool.query('UPDATE users SET last_login=NOW() WHERE id=$1', [user.id]);
    res.json({ token: token(user), user: safe(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed' }); }
});

app.get('/api/auth/profile', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.userId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(safe(r.rows[0]));
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/auth/audit', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM audit_logs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [req.user.userId]);
    res.json({ logs: r.rows });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── FILE ROUTES ──
app.post('/api/files/upload', auth, async (req, res) => {
  try {
    const { originalName, encryptedData, iv, algorithm, size } = req.body;
    if (!originalName || !encryptedData || !iv) return res.status(400).json({ error: 'Missing fields' });
    if (encryptedData.length > 14_000_000) return res.status(413).json({ error: 'File too large. Max ~10MB.' });
    const r = await pool.query(
      'INSERT INTO files (user_id,original_name,encrypted_data,iv,algorithm,size) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,original_name,size,uploaded_at',
      [req.user.userId, originalName, encryptedData, iv, algorithm || 'AES-GCM', size || 0]
    );
    await pool.query('INSERT INTO audit_logs (user_id,action,detail,ip) VALUES ($1,$2,$3,$4)', [req.user.userId, 'FILE_UPLOAD', originalName, req.ip]);
    res.status(201).json({ message: 'File uploaded', file: r.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Upload failed' }); }
});

app.get('/api/files', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT id,original_name,size,algorithm,iv,shared,uploaded_at FROM files WHERE user_id=$1 ORDER BY uploaded_at DESC',
      [req.user.userId]
    );
    res.json({ files: r.rows });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/files/:id', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT f.* FROM files f
       LEFT JOIN file_shares fs ON fs.file_id=f.id AND fs.shared_with_id=$1
       WHERE f.id=$2 AND (f.user_id=$1 OR fs.id IS NOT NULL)`,
      [req.user.userId, req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'File not found' });
    const f = r.rows[0];
    await pool.query('INSERT INTO audit_logs (user_id,action,detail,ip) VALUES ($1,$2,$3,$4)', [req.user.userId, 'FILE_DOWNLOAD', f.original_name, req.ip]);
    res.json({ encryptedData: f.encrypted_data, iv: f.iv, algorithm: f.algorithm, originalName: f.original_name });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/files/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM files WHERE id=$1 AND user_id=$2 RETURNING original_name', [req.params.id, req.user.userId]);
    if (!r.rows.length) return res.status(404).json({ error: 'File not found' });
    res.json({ message: 'Deleted' });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── SHARE ROUTES ──
app.post('/api/share', auth, async (req, res) => {
  try {
    const { fileId, shareWithEmail, message } = req.body;
    if (!fileId || !shareWithEmail) return res.status(400).json({ error: 'fileId and email required' });
    const file = await pool.query('SELECT * FROM files WHERE id=$1 AND user_id=$2', [fileId, req.user.userId]);
    if (!file.rows.length) return res.status(404).json({ error: 'File not found' });
    const recip = await pool.query('SELECT id,full_name,email FROM users WHERE email=$1', [shareWithEmail.toLowerCase()]);
    if (!recip.rows.length) return res.status(404).json({ error: 'No user with that email' });
    if (recip.rows[0].id === req.user.userId) return res.status(400).json({ error: 'Cannot share with yourself' });
    await pool.query(
      'INSERT INTO file_shares (file_id,owner_id,shared_with_id,message) VALUES ($1,$2,$3,$4) ON CONFLICT (file_id,shared_with_id) DO NOTHING',
      [fileId, req.user.userId, recip.rows[0].id, message || null]
    );
    await pool.query('UPDATE files SET shared=true WHERE id=$1', [fileId]);
    res.status(201).json({ message: `Shared with ${recip.rows[0].full_name}` });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Share failed' }); }
});

app.get('/api/share/with-me', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT fs.id as share_id,fs.message,fs.created_at,
              f.id as file_id,f.original_name,f.size,f.iv,f.algorithm,
              u.full_name as owner_name,u.email as owner_email
       FROM file_shares fs
       JOIN files f ON fs.file_id=f.id
       JOIN users u ON fs.owner_id=u.id
       WHERE fs.shared_with_id=$1 ORDER BY fs.created_at DESC`,
      [req.user.userId]
    );
    res.json({ shares: r.rows });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/share/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM file_shares WHERE id=$1 AND owner_id=$2 RETURNING id', [req.params.id, req.user.userId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Share not found' });
    res.json({ message: 'Revoked' });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── START ──
initDB().then(() => {
  app.listen(PORT, () => console.log(`SCBS backend running on port ${PORT}`));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });
