const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  const client = await pool.connect();
  try {
    console.log('Running DB migrations...');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255),
        role VARCHAR(20) DEFAULT 'user',
        verified BOOLEAN DEFAULT false,
        verify_token VARCHAR(255),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        original_name VARCHAR(500) NOT NULL,
        encrypted_data TEXT NOT NULL,
        iv VARCHAR(255) NOT NULL,
        algorithm VARCHAR(50) DEFAULT 'AES-GCM',
        size BIGINT NOT NULL,
        shared BOOLEAN DEFAULT false,
        uploaded_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS file_shares (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        file_id UUID REFERENCES files(id) ON DELETE CASCADE,
        owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
        shared_with_id UUID REFERENCES users(id) ON DELETE CASCADE,
        message TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(file_id, shared_with_id)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID,
        action VARCHAR(100) NOT NULL,
        detail VARCHAR(500),
        ip VARCHAR(100),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    console.log('DB ready ✓');
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB };
