require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const fileRoutes = require('./routes/files');
const shareRoutes = require('./routes/share');
const { initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;

// ── Security ──
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ── Rate limiting ──
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// ── Routes ──
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/share', shareRoutes);

// ── Health check ──
app.get('/health', (req, res) => {
  res.json({ status: 'OK', version: '1.0.0', time: new Date().toISOString() });
});

// ── Error handler ──
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

// ── Start ──
async function start() {
  await initDB();
  app.listen(PORT, () => console.log(`SCBS backend running on port ${PORT}`));
}
start();
