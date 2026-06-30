const cluster = require('cluster');
const http = require('http');
const WebSocket = require('ws');

if (!cluster.isPrimary) {
  if (process.env.ROLE === 'db') {
    require('./db-worker');
  } else if (process.env.ROLE === 'server') {
    require('./server-worker');
  } else if (process.env.ROLE === 'client') {
    require('./client-worker');
  } else {
    console.error(`Unknown worker role: ${process.env.ROLE}`);
    process.exit(1);
  }
  return;
}

const {
  CLIENT_COUNT,
  EXIT_WHEN_DONE,
  HOST,
  MESSAGE_STATE_TTL_MS,
  MESSAGES_PER_CLIENT,
  PORT,
  SERVER_URL,
  SERVER_WORKERS,
} = require('./config');
const { sendJsonNow } = require('./helpers');

const roles = new Map();
const connections = new Map();
const onlineClients = new Map();
const pendingDbRequests = new Map();
const pendingDeliveries = new Map();
const messageStates = new Map();
const finishedClients = new Set();
const clientResults = new Map();
const demoClientNames = new Set();

let dbWorker = null;
let dbReady = false;
let httpServer = null;
let wss = null;
let dbRequestNumber = 0;
let deliveryNumber = 0;
let connectionNumber = 0;
let socketNumber = 0;
let shuttingDown = false;
let demoStarted = false;

function forkRole(role, extraEnv = {}) {
  const worker = cluster.fork({
    ...process.env,
    ...extraEnv,
    ROLE: role,
  });

  roles.set(worker.id, role);
  return worker;
}

function serverWorkers() {
  return Object.values(cluster.workers).filter(
    (worker) => worker && !worker.isDead() && roles.get(worker.id) === 'server'
  );
}

function sendToWorker(workerId, packet) {
  const worker = cluster.workers[workerId];
  if (!worker || worker.isDead()) {
    return false;
  }

  worker.send(packet);
  return true;
}

function sendToSocket(connectionId, payload) {
  const connection = connections.get(connectionId);
  if (!connection || connection.ws.readyState !== WebSocket.OPEN) {
    return false;
  }

  return sendJsonNow(connection.ws, payload);
}

function closeSocket(connectionId, reason) {
  const connection = connections.get(connectionId);
  if (!connection) {
    return;
  }

  connection.ws.close(4001, reason || 'connection closed by server');
}

function removeClientsOfWorker(workerId) {
  for (const [name, client] of onlineClients.entries()) {
    if (client.workerId === workerId) {
      onlineClients.delete(name);
    }
  }

  for (const [connectionId, connection] of connections.entries()) {
    if (connection.workerId === workerId) {
      connection.ws.close(1011, 'server worker restarted');
      connections.delete(connectionId);
    }
  }
}

function askDb(op, payload, callback) {
  if (!dbReady || !dbWorker || dbWorker.isDead()) {
    callback({
      ok: false,
      error: 'DB worker is not ready',
    });
    return;
  }

  dbRequestNumber += 1;
  const requestId = `primary-${process.pid}-db-${dbRequestNumber}`;
  pendingDbRequests.set(requestId, callback);

  dbWorker.send({
    ...payload,
    channel: 'db:request',
    requestId,
    op,
  });
}

function askDbPromise(op, payload = {}) {
  return new Promise((resolve) => askDb(op, payload, resolve));
}

function sendRouteResult(workerId, routeId, result) {
  sendToWorker(workerId, {
    channel: 'route_result',
    routeId,
    ...result,
  });
}

function finishMessage(messageId, result) {
  const state = messageStates.get(messageId);
  if (!state) {
    return;
  }

  state.status = 'done';
  state.result = result;

  for (const waiter of state.waiters) {
    sendRouteResult(waiter.workerId, waiter.routeId, result);
  }

  state.waiters = [];

  setTimeout(() => {
    const current = messageStates.get(messageId);
    if (current && current.status === 'done') {
      messageStates.delete(messageId);
    }
  }, MESSAGE_STATE_TTL_MS).unref();
}

function storeOffline(message) {
  askDb('store_offline', { message }, (response) => {
    finishMessage(message.id, {
      ok: response.ok,
      delivery: 'offline',
      error: response.error || null,
    });
  });
}

function deliverOrStore(message) {
  const target = onlineClients.get(message.to);

  if (!target) {
    storeOffline(message);
    return;
  }

  deliveryNumber += 1;
  const deliveryId = `delivery-${process.pid}-${deliveryNumber}`;

  const sent = sendToWorker(target.workerId, {
    channel: 'deliver_live',
    deliveryId,
    message,
  });

  if (!sent) {
    onlineClients.delete(message.to);
    storeOffline(message);
    return;
  }

  pendingDeliveries.set(deliveryId, {
    message,
    targetWorkerId: target.workerId,
  });
}

function handleRouteMessage(worker, packet) {
  const message = packet.message;
  const existing = messageStates.get(message.id);

  if (existing) {
    if (existing.status === 'done') {
      sendRouteResult(worker.id, packet.routeId, existing.result);
      return;
    }

    existing.waiters.push({
      workerId: worker.id,
      routeId: packet.routeId,
    });
    return;
  }

  messageStates.set(message.id, {
    status: 'processing',
    waiters: [
      {
        workerId: worker.id,
        routeId: packet.routeId,
      },
    ],
  });

  deliverOrStore(message);
}

function handleLiveDeliveryResult(packet) {
  const pending = pendingDeliveries.get(packet.deliveryId);
  if (!pending) {
    return;
  }

  pendingDeliveries.delete(packet.deliveryId);

  if (packet.ok) {
    finishMessage(pending.message.id, {
      ok: true,
      delivery: 'live',
      error: null,
    });
    return;
  }

  const online = onlineClients.get(pending.message.to);
  if (online && online.workerId === pending.targetWorkerId) {
    onlineClients.delete(pending.message.to);
  }

  storeOffline(pending.message);
}

function handleClientOnline(worker, packet) {
  const oldClient = onlineClients.get(packet.name);

  if (oldClient && oldClient.workerId !== worker.id) {
    sendToWorker(oldClient.workerId, {
      channel: 'close_client',
      name: packet.name,
    });
  }

  const connection = connections.get(packet.connectionId);
  if (connection) {
    connection.clientName = packet.name;
  }

  onlineClients.set(packet.name, {
    workerId: worker.id,
    connectionId: packet.connectionId,
  });

  maybeStartDemoClients();
}

function handleClientOffline(worker, packet) {
  const online = onlineClients.get(packet.name);
  if (online && online.workerId === worker.id) {
    onlineClients.delete(packet.name);
  }
}

function forwardDbRequest(worker, packet) {
  askDb(packet.op, packet, (response) => {
    sendToWorker(worker.id, {
      ...response,
      channel: 'db:response',
      requestId: packet.requestId,
    });
  });
}

function handleDbResponse(packet) {
  const callback = pendingDbRequests.get(packet.requestId);
  if (!callback) {
    return;
  }

  pendingDbRequests.delete(packet.requestId);
  callback(packet);
}

function handleSendToSocket(worker, packet) {
  const ok = sendToSocket(packet.connectionId, packet.payload);

  sendToWorker(worker.id, {
    channel: 'socket_send_result',
    requestId: packet.requestId,
    ok,
  });
}

function handleSocketConnection(ws) {
  const workers = serverWorkers();
  if (!workers.length) {
    ws.close(1013, 'server workers are not ready');
    return;
  }

  connectionNumber += 1;
  const connectionId = `connection-${process.pid}-${connectionNumber}`;
  const worker = workers[socketNumber % workers.length];
  socketNumber += 1;

  connections.set(connectionId, {
    ws,
    workerId: worker.id,
    clientName: null,
  });

  ws.on('message', (raw) => {
    const connection = connections.get(connectionId);
    if (!connection) {
      return;
    }

    sendToWorker(connection.workerId, {
      channel: 'socket_message',
      connectionId,
      clientName: connection.clientName,
      data: raw.toString(),
    });
  });

  ws.on('close', () => {
    const connection = connections.get(connectionId);
    if (!connection) {
      return;
    }

    connections.delete(connectionId);

    sendToWorker(connection.workerId, {
      channel: 'socket_closed',
      connectionId,
      clientName: connection.clientName,
    });
  });
}

function startDbWorker() {
  dbReady = false;
  dbWorker = forkRole('db');
  console.log(`[primary] DB worker started, pid=${dbWorker.process.pid}`);
}

function startServerWorkers() {
  for (let i = 0; i < SERVER_WORKERS; i += 1) {
    const worker = forkRole('server');
    console.log(`[primary] server worker started, pid=${worker.process.pid}`);
  }
}

function startWebSocketServer() {
  httpServer = http.createServer();
  wss = new WebSocket.Server({ server: httpServer });

  wss.on('connection', handleSocketConnection);

  httpServer.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      console.error(`[primary] Port ${PORT} is busy. Run with another port, for example: PORT=8090 npm start`);
    } else {
      console.error(`[primary] listen error: ${error.message}`);
    }

    shutdown(1);
  });

  httpServer.listen(PORT, HOST, () => {
    console.log(`[primary] WebSocket server listens on ws://${HOST}:${PORT}`);

    if (process.env.START_CLIENTS === '1') {
      setTimeout(startClientWorkers, 800);
    }
  });
}

function startClientWorkers() {
  const names = Array.from({ length: CLIENT_COUNT }, (_, index) => `client-${index}`);
  demoClientNames.clear();
  demoStarted = false;

  for (const name of names) {
    demoClientNames.add(name);
    const peers = names.filter((peerName) => peerName !== name);
    const worker = forkRole('client', {
      CLIENT_NAME: name,
      CLIENT_PEERS: JSON.stringify(peers),
      MESSAGES_PER_CLIENT: String(MESSAGES_PER_CLIENT),
      SERVER_URL,
    });

    console.log(`[primary] client worker ${name} started, pid=${worker.process.pid}`);
  }
}

function maybeStartDemoClients() {
  if (process.env.START_CLIENTS !== '1' || demoStarted || demoClientNames.size === 0) {
    return;
  }

  for (const name of demoClientNames) {
    if (!onlineClients.has(name)) {
      return;
    }
  }

  demoStarted = true;
  console.log('[primary] all demo clients registered, starting message exchange');

  for (const name of demoClientNames) {
    const client = onlineClients.get(name);
    if (client) {
      sendToSocket(client.connectionId, { type: 'start' });
    }
  }
}

async function printFinalState() {
  const response = await askDbPromise('offline_count');
  if (response.ok) {
    console.log(`[primary] offline messages in DB: ${response.count}`);
  }
}

function mergeMatrix(target, source = {}) {
  for (const [from, row] of Object.entries(source)) {
    if (!target[from]) {
      target[from] = {};
    }

    for (const [to, count] of Object.entries(row || {})) {
      target[from][to] = (target[from][to] || 0) + Number(count || 0);
    }
  }
}

function sumMatrix(matrix) {
  let total = 0;

  for (const row of Object.values(matrix)) {
    for (const count of Object.values(row)) {
      total += Number(count || 0);
    }
  }

  return total;
}

function printMatrixCheck() {
  const sent = {};
  const received = {};

  for (const result of clientResults.values()) {
    mergeMatrix(sent, result.sentMatrix);
    mergeMatrix(received, result.receivedMatrix);
  }

  const pairs = new Set();

  for (const [from, row] of Object.entries(sent)) {
    for (const to of Object.keys(row)) {
      pairs.add(`${from}->${to}`);
    }
  }

  for (const [from, row] of Object.entries(received)) {
    for (const to of Object.keys(row)) {
      pairs.add(`${from}->${to}`);
    }
  }

  const mismatches = [];

  for (const pair of pairs) {
    const [from, to] = pair.split('->');
    const sentCount = sent[from]?.[to] || 0;
    const receivedCount = received[from]?.[to] || 0;

    if (sentCount !== receivedCount) {
      mismatches.push({ from, to, sentCount, receivedCount });
    }
  }

  console.log(`[primary] matrix total sent=${sumMatrix(sent)}, received=${sumMatrix(received)}`);

  if (!mismatches.length) {
    console.log('[primary] matrix check: OK, sent and received counters are equal');
    return;
  }

  console.log('[primary] matrix check: mismatches found');
  for (const mismatch of mismatches.slice(0, 10)) {
    console.log(
      `[primary] ${mismatch.from}->${mismatch.to}: sent=${mismatch.sentCount}, received=${mismatch.receivedCount}`
    );
  }
}

async function shutdown(exitCode = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;

  if (wss) {
    wss.close();
  }

  if (httpServer) {
    httpServer.close();
  }

  for (const connection of connections.values()) {
    connection.ws.close(1001, 'server stopped');
  }

  try {
    if (dbReady) {
      await printFinalState();
    }
  } catch (error) {
    console.error(`[primary] final DB check failed: ${error.message}`);
  }

  for (const worker of Object.values(cluster.workers)) {
    if (worker && !worker.isDead()) {
      worker.process.kill('SIGTERM');
    }
  }

  setTimeout(() => process.exit(exitCode), 300);
}

function maybeStopAfterClientsDone() {
  if (!EXIT_WHEN_DONE || process.env.START_CLIENTS !== '1') {
    return;
  }

  if (finishedClients.size !== CLIENT_COUNT) {
    return;
  }

  console.log('[primary] all client workers finished');
  printMatrixCheck();
  setTimeout(() => shutdown(0), 1000);
}

cluster.on('message', (worker, packet) => {
  if (!packet || !packet.channel) {
    return;
  }

  if (packet.channel === 'db:ready') {
    dbReady = true;
    console.log(`[primary] DB is ready: ${packet.dbFile}, pool=${packet.poolSize}`);
    startServerWorkers();
    startWebSocketServer();
    return;
  }

  if (packet.channel === 'db:response') {
    handleDbResponse(packet);
    return;
  }

  if (packet.channel === 'db:request') {
    forwardDbRequest(worker, packet);
    return;
  }

  if (packet.channel === 'send_to_socket') {
    handleSendToSocket(worker, packet);
    return;
  }

  if (packet.channel === 'close_socket') {
    closeSocket(packet.connectionId, packet.reason);
    return;
  }

  if (packet.channel === 'client_online') {
    handleClientOnline(worker, packet);
    return;
  }

  if (packet.channel === 'client_offline') {
    handleClientOffline(worker, packet);
    return;
  }

  if (packet.channel === 'route_message') {
    handleRouteMessage(worker, packet);
    return;
  }

  if (packet.channel === 'deliver_live_result') {
    handleLiveDeliveryResult(packet);
    return;
  }

  if (packet.channel === 'client_done') {
    finishedClients.add(worker.id);
    clientResults.set(worker.id, packet);
    console.log(
      `[primary] ${packet.name}: sent=${packet.sentTotal}, received=${packet.receivedTotal}`
    );
    maybeStopAfterClientsDone();
  }
});

cluster.on('exit', (worker, code, signal) => {
  const role = roles.get(worker.id);
  roles.delete(worker.id);
  removeClientsOfWorker(worker.id);

  if (shuttingDown) {
    return;
  }

  if (role === 'db') {
    console.log(`[primary] DB worker exited (${signal || code}), restarting`);
    startDbWorker();
    return;
  }

  if (role === 'server') {
    console.log(`[primary] server worker exited (${signal || code}), restarting`);
    const newWorker = forkRole('server');
    console.log(`[primary] server worker started, pid=${newWorker.process.pid}`);
  }
});

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

console.log('[primary] starting messenger');
startDbWorker();
