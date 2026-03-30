const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: config.databaseSsl ? { rejectUnauthorized: false } : false
});

async function testConnection() {
  const result = await pool.query('SELECT 1 AS ok');
  return result.rows[0]?.ok === 1;
}

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS operation_orders (
      id BIGSERIAL PRIMARY KEY,
      order_code VARCHAR(100) NOT NULL UNIQUE,
      current_status VARCHAR(50) NOT NULL DEFAULT 'pending',
      assigned_to_user_id VARCHAR(100),
      priority SMALLINT NOT NULL DEFAULT 0,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS operation_actions (
      id BIGSERIAL PRIMARY KEY,
      order_code VARCHAR(100) NOT NULL,
      action_type VARCHAR(100) NOT NULL,
      by_user_id VARCHAR(100) NOT NULL,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS operation_notes (
      id BIGSERIAL PRIMARY KEY,
      order_code VARCHAR(100) NOT NULL,
      note TEXT NOT NULL,
      by_user_id VARCHAR(100) NOT NULL,
      visibility VARCHAR(30) NOT NULL DEFAULT 'internal',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS qa_orders (
      id BIGSERIAL PRIMARY KEY,
      order_code VARCHAR(100) NOT NULL UNIQUE,
      sku VARCHAR(150) NOT NULL,
      product_name VARCHAR(255) NOT NULL,
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      created_by VARCHAR(100),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_operation_orders_assigned_to ON operation_orders(assigned_to_user_id);'
  );
  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_operation_orders_status ON operation_orders(current_status);'
  );
  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_operation_actions_order_code ON operation_actions(order_code);'
  );
  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_operation_notes_order_code ON operation_notes(order_code);'
  );
  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_qa_orders_order_code ON qa_orders(order_code);'
  );
  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_qa_orders_created_at ON qa_orders(created_at DESC);'
  );
}

module.exports = {
  pool,
  testConnection,
  initSchema
};
