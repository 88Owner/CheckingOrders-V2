const path = require('path');
const dotenv = require('dotenv');

dotenv.config({
  path: process.env.OPERATIONS_ENV_FILE || path.resolve(process.cwd(), '.env')
});

const config = {
  port: Number(process.env.OPERATIONS_PORT || process.env.PORT || 3010),
  nodeEnv: process.env.NODE_ENV || 'development',
  sharedAuthSecret:
    process.env.OPERATIONS_SHARED_AUTH_SECRET ||
    process.env.SESSION_SECRET ||
    'change_this_session_secret_in_production',
  mainAppUrl:
    process.env.MAIN_APP_URL || 'https://spice-investigated-allowed-dom.trycloudflare.com',
  databaseUrl:
    process.env.OPERATIONS_DATABASE_URL ||
    process.env.DATABASE_URL ||
    'postgresql://operations_user:operations_password@localhost:5432/operations_db',
  databaseSsl: (process.env.OPERATIONS_DATABASE_SSL || 'false').toLowerCase() === 'true'
};

module.exports = config;
