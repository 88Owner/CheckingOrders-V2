const app = require('./app');
const config = require('./config');
const { initSchema, testConnection, pool } = require('./db');

async function start() {
  try {
    await testConnection();
    await initSchema();

    app.listen(config.port, '0.0.0.0', () => {
      console.log(`[operations-service] running on port ${config.port}`);
    });
  } catch (error) {
    console.error('[operations-service] failed to start:', error);
    process.exit(1);
  }
}

process.on('SIGTERM', async () => {
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  await pool.end();
  process.exit(0);
});

start();
