const os = require('os');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT_DIR, 'data');

const cpuCount =
  typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : os.cpus().length;

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8080);

module.exports = {
  ROOT_DIR,
  DATA_DIR,
  DB_FILE: process.env.DB_FILE || path.join(DATA_DIR, 'messages.sqlite'),
  HOST,
  PORT,
  SERVER_URL: process.env.SERVER_URL || `ws://${HOST}:${PORT}`,
  SERVER_WORKERS: Number(process.env.SERVER_WORKERS || cpuCount),
  CLIENT_COUNT: Number(process.env.CLIENT_COUNT || 10),
  MESSAGES_PER_CLIENT: Number(process.env.MESSAGES_PER_CLIENT || 100000),
  DB_POOL_SIZE: Number(process.env.DB_POOL_SIZE || 4),
  DB_BATCH_SIZE: Number(process.env.DB_BATCH_SIZE || 500),
  DB_BATCH_DELAY_MS: Number(process.env.DB_BATCH_DELAY_MS || 25),
  OFFLINE_FETCH_LIMIT: Number(process.env.OFFLINE_FETCH_LIMIT || 10000),
  ACK_TIMEOUT_MS: Number(process.env.ACK_TIMEOUT_MS || 5000),
  CLIENT_PROGRESS_INTERVAL_MS: Number(process.env.CLIENT_PROGRESS_INTERVAL_MS || 5000),
  MESSAGE_STATE_TTL_MS: Number(process.env.MESSAGE_STATE_TTL_MS || 120000),
  EXIT_WHEN_DONE: process.env.EXIT_WHEN_DONE === '1',
};
