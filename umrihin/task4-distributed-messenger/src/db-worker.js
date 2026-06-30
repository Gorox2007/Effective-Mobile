const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3');

const {
  DB_BATCH_DELAY_MS,
  DB_BATCH_SIZE,
  DB_FILE,
  DB_POOL_SIZE,
  OFFLINE_FETCH_LIMIT,
} = require('./config');

let pool = [];
let readIndex = 0;
let storeQueue = [];
let flushTimer = null;
let flushPromise = null;

function openDatabase(fileName) {
  return new Promise((resolve, reject) => {
    const database = new sqlite3.Database(fileName, (error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve({
        run(sql, params = []) {
          return new Promise((runResolve, runReject) => {
            database.run(sql, params, function onRun(runError) {
              if (runError) {
                runReject(runError);
                return;
              }

              runResolve({ lastID: this.lastID, changes: this.changes });
            });
          });
        },
        all(sql, params = []) {
          return new Promise((allResolve, allReject) => {
            database.all(sql, params, (allError, rows) => {
              if (allError) {
                allReject(allError);
                return;
              }

              allResolve(rows || []);
            });
          });
        },
        get(sql, params = []) {
          return new Promise((getResolve, getReject) => {
            database.get(sql, params, (getError, row) => {
              if (getError) {
                getReject(getError);
                return;
              }

              getResolve(row || null);
            });
          });
        },
        exec(sql) {
          return new Promise((execResolve, execReject) => {
            database.exec(sql, (execError) => {
              if (execError) {
                execReject(execError);
                return;
              }

              execResolve();
            });
          });
        },
        close() {
          return new Promise((closeResolve) => database.close(() => closeResolve()));
        },
      });
    });
  });
}

function readDb() {
  const database = pool[readIndex % pool.length];
  readIndex += 1;
  return database;
}

function writeDb() {
  return pool[0];
}

async function init() {
  await fs.promises.mkdir(path.dirname(DB_FILE), { recursive: true });

  for (let i = 0; i < DB_POOL_SIZE; i += 1) {
    const database = await openDatabase(DB_FILE);
    await database.run('PRAGMA busy_timeout = 5000');
    pool.push(database);
  }

  if (process.env.RESET_DB === '1') {
    await writeDb().exec('DROP TABLE IF EXISTS offline_messages;');
  }

  await writeDb().exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS offline_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id TEXT NOT NULL UNIQUE,
      from_name TEXT NOT NULL,
      to_name TEXT NOT NULL,
      message_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_offline_messages_to_name
      ON offline_messages (to_name, id);
  `);
}

function reply(requestId, ok, payload = {}) {
  if (!requestId || !process.send) {
    return;
  }

  process.send({
    channel: 'db:response',
    requestId,
    ok,
    ...payload,
  });
}

async function transaction(task) {
  const database = writeDb();
  await database.run('BEGIN IMMEDIATE TRANSACTION');

  try {
    const result = await task(database);
    await database.run('COMMIT');
    return result;
  } catch (error) {
    await database.run('ROLLBACK');
    throw error;
  }
}

async function flushStoreQueue() {
  if (flushPromise) {
    return flushPromise;
  }

  if (!storeQueue.length) {
    return Promise.resolve();
  }

  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  const batch = storeQueue.splice(0, storeQueue.length);

  flushPromise = transaction(async (database) => {
    for (const item of batch) {
      const message = item.message;
      await database.run(
        `
          INSERT OR IGNORE INTO offline_messages
            (message_id, from_name, to_name, message_json)
          VALUES (?, ?, ?, ?)
        `,
        [
          message.id,
          message.from,
          message.to,
          JSON.stringify(message),
        ]
      );
    }
  })
    .then(() => {
      for (const item of batch) {
        reply(item.requestId, true, { stored: true });
      }
    })
    .catch((error) => {
      for (const item of batch) {
        reply(item.requestId, false, { error: error.message });
      }
    })
    .finally(() => {
      flushPromise = null;
      if (storeQueue.length) {
        scheduleFlush();
      }
    });

  return flushPromise;
}

function scheduleFlush() {
  if (flushTimer) {
    return;
  }

  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushStoreQueue().catch((error) => {
      console.error(`[db] batch write error: ${error.message}`);
    });
  }, DB_BATCH_DELAY_MS);
}

function storeOffline(requestId, message) {
  storeQueue.push({ requestId, message });

  if (storeQueue.length >= DB_BATCH_SIZE) {
    flushStoreQueue().catch((error) => {
      console.error(`[db] batch write error: ${error.message}`);
    });
    return;
  }

  scheduleFlush();
}

async function fetchOffline(requestId, toName) {
  await flushStoreQueue();

  const rows = await readDb().all(
    `
      SELECT id, message_json
      FROM offline_messages
      WHERE to_name = ?
      ORDER BY id
      LIMIT ?
    `,
    [toName, OFFLINE_FETCH_LIMIT]
  );

  const messages = rows.map((row) => ({
    dbId: row.id,
    message: JSON.parse(row.message_json),
  }));

  reply(requestId, true, { messages });
}

async function deleteOffline(requestId, ids) {
  const cleanIds = [...new Set((ids || []).map(Number).filter(Boolean))];

  if (!cleanIds.length) {
    reply(requestId, true, { deleted: 0 });
    return;
  }

  const deleted = await transaction(async (database) => {
    const placeholders = cleanIds.map(() => '?').join(', ');
    const result = await database.run(
      `DELETE FROM offline_messages WHERE id IN (${placeholders})`,
      cleanIds
    );
    return result.changes;
  });

  reply(requestId, true, { deleted });
}

async function getOfflineCount(requestId) {
  await flushStoreQueue();
  const row = await readDb().get('SELECT COUNT(*) AS count FROM offline_messages');
  reply(requestId, true, { count: row ? row.count : 0 });
}

async function handleMessage(packet) {
  if (!packet || packet.channel !== 'db:request') {
    return;
  }

  try {
    if (packet.op === 'store_offline') {
      storeOffline(packet.requestId, packet.message);
      return;
    }

    if (packet.op === 'fetch_offline') {
      await fetchOffline(packet.requestId, packet.toName);
      return;
    }

    if (packet.op === 'delete_offline') {
      await deleteOffline(packet.requestId, packet.ids);
      return;
    }

    if (packet.op === 'offline_count') {
      await getOfflineCount(packet.requestId);
      return;
    }

    reply(packet.requestId, false, { error: `Unknown DB operation: ${packet.op}` });
  } catch (error) {
    reply(packet.requestId, false, { error: error.message });
  }
}

async function shutdown() {
  await flushStoreQueue();
  await Promise.all(pool.map((database) => database.close()));
  process.exit(0);
}

init()
  .then(() => {
    process.on('message', handleMessage);
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    if (process.send) {
      process.send({
        channel: 'db:ready',
        dbFile: DB_FILE,
        poolSize: DB_POOL_SIZE,
      });
    }
  })
  .catch((error) => {
    console.error(`[db] start error: ${error.message}`);
    process.exit(1);
  });
