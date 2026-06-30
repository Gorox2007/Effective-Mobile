const WebSocket = require('ws');

const {
  ACK_TIMEOUT_MS,
  CLIENT_PROGRESS_INTERVAL_MS,
  MESSAGES_PER_CLIENT,
  SERVER_URL,
} = require('./config');
const {
  incrementMatrix,
  makeMessageId,
  parseJson,
  randomItem,
  sendJsonNow,
} = require('./helpers');

const name = process.env.CLIENT_NAME || `client-${process.pid}`;
const peers = JSON.parse(process.env.CLIENT_PEERS || '[]');

const sentMatrix = {};
const receivedMatrix = {};
const pendingMessages = new Map();

let ws = null;
let connectionNumber = 0;
let reconnectDelay = 500;
let messageNumber = 0;
let sentTotal = 0;
let receivedTotal = 0;
let registered = false;
let started = false;
let doneReported = false;
let pumpTimer = null;
let reconnectTimer = null;
let lastProgressLineAt = 0;

const BURST_SIZE = Number(process.env.CLIENT_BURST_SIZE || 100);
const MAX_BUFFERED_AMOUNT = Number(process.env.MAX_BUFFERED_AMOUNT || 1024 * 1024);

function scheduleReconnect() {
  if (doneReported) {
    return;
  }

  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(connect, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, 30000);
}

function reportDone() {
  if (doneReported) {
    return;
  }

  doneReported = true;

  setTimeout(() => {
    if (process.send) {
      process.send({
        channel: 'client_done',
        name,
        sentTotal,
        receivedTotal,
        sentMatrix,
        receivedMatrix,
      });
    }

  }, 700);
}

function sendPacket(packet) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return false;
  }

  return sendJsonNow(ws, packet);
}

function resendPendingMessages() {
  const now = Date.now();

  for (const item of pendingMessages.values()) {
    const alreadySentOnThisConnection = item.connectionNumber === connectionNumber;
    const recentlySent = now - item.lastSendAt < ACK_TIMEOUT_MS;

    if (alreadySentOnThisConnection && recentlySent) {
      continue;
    }

    if (ws.bufferedAmount > MAX_BUFFERED_AMOUNT) {
      return;
    }

    item.connectionNumber = connectionNumber;
    item.lastSendAt = now;
    sendPacket(item.packet);
  }
}

function printProgress() {
  const now = Date.now();

  if (now - lastProgressLineAt < CLIENT_PROGRESS_INTERVAL_MS) {
    return;
  }

  lastProgressLineAt = now;

  if (pendingMessages.size > 0 || sentTotal < MESSAGES_PER_CLIENT) {
    console.log(
      `[client ${name}] progress sent=${sentTotal}/${MESSAGES_PER_CLIENT}, pending=${pendingMessages.size}, received=${receivedTotal}`
    );
  }
}

function createNewMessage() {
  messageNumber += 1;
  const to = randomItem(peers);
  const id = makeMessageId(name, messageNumber);
  const packet = {
    type: 'message',
    id,
    to,
    text: `message ${messageNumber} from ${name}`,
    sentAt: new Date().toISOString(),
  };

  pendingMessages.set(id, {
    to,
    packet,
    connectionNumber,
    lastSendAt: Date.now(),
  });

  sendPacket(packet);
}

function pump() {
  clearTimeout(pumpTimer);

  if (!started || !registered || !ws || ws.readyState !== WebSocket.OPEN || !peers.length) {
    return;
  }

  resendPendingMessages();
  printProgress();

  if (sentTotal >= MESSAGES_PER_CLIENT && pendingMessages.size === 0) {
    reportDone();
    return;
  }

  if (ws.bufferedAmount > MAX_BUFFERED_AMOUNT) {
    pumpTimer = setTimeout(pump, 20);
    return;
  }

  let created = 0;
  while (
    created < BURST_SIZE &&
    sentTotal + pendingMessages.size < MESSAGES_PER_CLIENT &&
    ws.bufferedAmount <= MAX_BUFFERED_AMOUNT
  ) {
    createNewMessage();
    created += 1;
  }

  pumpTimer = setTimeout(pump, 0);
}

function handlePacket(packet) {
  if (packet.type === 'registered') {
    registered = true;
    reconnectDelay = 500;
    if (started) {
      pump();
    }
    return;
  }

  if (packet.type === 'start') {
    started = true;
    pump();
    return;
  }

  if (packet.type === 'sent_ack') {
    const pending = pendingMessages.get(packet.id);

    if (pending && packet.ok) {
      pendingMessages.delete(packet.id);
      sentTotal += 1;
      incrementMatrix(sentMatrix, name, pending.to);
    }

    pump();
    return;
  }

  if (packet.type === 'message') {
    receivedTotal += 1;
    incrementMatrix(receivedMatrix, packet.from, name);
  }
}

function connect() {
  clearTimeout(reconnectTimer);
  connectionNumber += 1;

  ws = new WebSocket(SERVER_URL);

  ws.on('open', () => {
    sendJsonNow(ws, {
      type: 'register',
      name,
    });
  });

  ws.on('message', (raw) => {
    const packet = parseJson(raw);
    if (packet) {
      handlePacket(packet);
    }
  });

  ws.on('close', () => {
    registered = false;
    clearTimeout(pumpTimer);
    scheduleReconnect();
  });

  ws.on('error', () => {});
}

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

console.log(`[client ${name}] connects to ${SERVER_URL}`);
connect();
