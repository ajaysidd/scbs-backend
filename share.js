const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { authenticate } = require('../middleware/auth');

// ── SHARE A FILE ──
router.post('/', authenticate, async (req, res) => {
  try {
    const { fileId, shareWithEmail, message } = req.body;
    if (!fileId || !shareWithEmail)
      return res.status(400).json({ error: 'fileId and shareWithEmail required' });

    // Verify ownership
    const file = await pool.query(
      'SELECT * FROM files WHERE id=$1 AND user_id=$2',
      [fileId, req.user.userId]
    );
    if (!file.rows.length)
      return res.status(404).json({ error: 'File not found' });

    // Find recipient
    const recipient = await pool.query(
      'SELECT id, full_name, email FROM users WHERE email=$1',
      [shareWithEmail.toLowerCase()]
    );
    if (!recipient.rows.length)
      return res.status(404).json({ error: 'No user found with that email' });

    const recipientUser = recipient.rows[0];
    if (recipientUser.id === req.user.userId)
      return res.status(400).json({ error: 'Cannot share with yourself' });

    // Insert share (ignore if already shared)
    await pool.query(
      `INSERT INTO file_shares (file_id, owner_id, shared_with_id, message)
       VALUES ($1,$2,$3,$4) ON CONFLICT (file_id, shared_with_id) DO NOTHING`,
      [fileId, req.user.userId, recipientUser.id, message || null]
    );

    // Mark file as shared
    await pool.query('UPDATE files SET shared=true WHERE id=$1', [fileId]);

    await pool.query(
      'INSERT INTO audit_logs (user_id, action, detail, ip) VALUES ($1,$2,$3,$4)',
      [req.user.userId, 'FILE_SHARE', `${file.rows[0].original_name} → ${shareWithEmail}`, req.ip]
    );

    res.status(201).json({
      message: `File shared with ${recipientUser.full_name}`,
      sharedWith: recipientUser.full_name,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Share failed' });
  }
});

// ── FILES SHARED WITH ME ──
router.get('/with-me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT fs.id as share_id, fs.message, fs.created_at,
              f.id as file_id, f.original_name, f.size, f.iv, f.algorithm,
              u.full_name as owner_name, u.email as owner_email
       FROM file_shares fs
       JOIN files f ON fs.file_id=f.id
       JOIN users u ON fs.owner_id=u.id
       WHERE fs.shared_with_id=$1
       ORDER BY fs.created_at DESC`,
      [req.user.userId]
    );
    res.json({ shares: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch shared files' });
  }
});

// ── REVOKE SHARE ──
router.delete('/:shareId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM file_shares WHERE id=$1 AND owner_id=$2 RETURNING id',
      [req.params.shareId, req.user.userId]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: 'Share not found' });
    res.json({ message: 'Share revoked' });
  } catch (err) {
    res.status(500).json({ error: 'Revoke failed' });
  }
});

module.exports = router;
