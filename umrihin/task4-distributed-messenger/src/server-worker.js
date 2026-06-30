const { cleanName, parseJson } = require('./helpers');

const activeClients = new Map();
const dbRequests = new Map();
const routeRequests = new Map();
const socketRequests = new Map();

let dbRequestNumber = 0;
let routeRequestNumber = 0;
let socketRequestNumber = 0;

function nextDbRequestId() {
  dbRequestNumber += 1;
  return `server-${process.pid}-db-${dbRequestNumber}`;
}

function nextRouteId() {
  routeRequestNumber += 1;
  return `server-${process.pid}-route-${routeRequestNumber}`;
}

function nextSocketRequestId() {
  socketRequestNumber += 1;
  return `server-${process.pid}-socket-${socketRequestNumber}`;
}

function askDb(op, payload) {
  const requestId = nextDbRequestId();

  return new Promise((resolve, reject) => {
    dbRequests.set(requestId, { resolve, reject });

    process.send({
      channel: 'db:request',
      requestId,
      op,
      ...payload,
    });
  });
}

function sendToSocket(connectionId, payload) {
  const requestId = nextSocketRequestId();

  return new Promise((resolve) => {
    socketRequests.set(requestId, resolve);

    process.send({
      channel: 'send_to_socket',
      requestId,
      connectionId,
      payload,
    });
  });
}

function sendSocketError(connectionId, message) {
  sendToSocket(connectionId, {
    type: 'error',
    message,
  }).catch(() => {});
}

async function deliverOfflineMessages(connectionId, clientName) {
  const response = await askDb('fetch_offline', { toName: clientName });
  const rows = response.messages || [];
  const deliveredIds = [];

  for (const row of rows) {
    if (activeClients.get(clientName) !== connectionId) {
      break;
    }

    const result = await sendToSocket(connectionId, {
      type: 'message',
      ...row.message,
      offline: true,
    });

    if (result.ok) {
      deliveredIds.push(row.dbId);
    } else {
      break;
    }
  }

  if (deliveredIds.length) {
    await askDb('delete_offline', { ids: deliveredIds });
  }

  return {
    found: rows.length,
    delivered: deliveredIds.length,
  };
}

async function registerClient(connectionId, rawName) {
  const name = cleanName(rawName);

  if (!name) {
    sendSocketError(connectionId, 'Name is required');
    return;
  }

  const oldConnectionId = activeClients.get(name);
  if (oldConnectionId && oldConnectionId !== connectionId) {
    process.send({
      channel: 'close_socket',
      connectionId: oldConnectionId,
      reason: 'same client name reconnected',
    });
  }

  activeClients.set(name, connectionId);

  process.send({
    channel: 'client_online',
    name,
    connectionId,
  });

  try {
    const offline = await deliverOfflineMessages(connectionId, name);

    if (activeClients.get(name) === connectionId) {
      await sendToSocket(connectionId, {
        type: 'registered',
        name,
        workerPid: process.pid,
        offlineFound: offline.found,
        offlineDelivered: offline.delivered,
      });
    }
  } catch (error) {
    sendSocketError(connectionId, `Offline fetch error: ${error.message}`);
  }
}

function routeMessage(connectionId, packet) {
  const from = cleanName(packet.fromName);

  if (!from) {
    sendSocketError(connectionId, 'Register before sending messages');
    return;
  }

  const to = cleanName(packet.to);
  if (!to) {
    sendSocketError(connectionId, 'Recipient is required');
    return;
  }

  const routeId = nextRouteId();
  const message = {
    id: String(packet.id || routeId),
    from,
    to,
    text: String(packet.text || ''),
    sentAt: packet.sentAt || new Date().toISOString(),
  };

  routeRequests.set(routeId, {
    connectionId,
    message,
  });

  process.send({
    channel: 'route_message',
    routeId,
    message,
  });
}

function handleClientPacket(connectionId, raw, fromName) {
  const packet = parseJson(raw);

  if (!packet || typeof packet !== 'object') {
    sendSocketError(connectionId, 'Invalid JSON');
    return;
  }

  if (packet.type === 'register') {
    registerClient(connectionId, packet.name);
    return;
  }

  if (packet.type === 'message') {
    routeMessage(connectionId, {
      ...packet,
      fromName,
    });
    return;
  }

  sendSocketError(connectionId, `Unknown type: ${packet.type}`);
}

async function deliverLive(deliveryId, message) {
  const connectionId = activeClients.get(message.to);

  if (!connectionId) {
    process.send({
      channel: 'deliver_live_result',
      deliveryId,
      ok: false,
    });
    return;
  }

  const result = await sendToSocket(connectionId, {
    type: 'message',
    ...message,
    offline: false,
  });

  process.send({
    channel: 'deliver_live_result',
    deliveryId,
    ok: result.ok,
  });
}

function handlePrimaryMessage(packet) {
  if (!packet || !packet.channel) {
    return;
  }

  if (packet.channel === 'socket_message') {
    handleClientPacket(packet.connectionId, packet.data, packet.clientName);
    return;
  }

  if (packet.channel === 'socket_closed') {
    if (packet.clientName && activeClients.get(packet.clientName) === packet.connectionId) {
      activeClients.delete(packet.clientName);
      process.send({
        channel: 'client_offline',
        name: packet.clientName,
      });
    }
    return;
  }

  if (packet.channel === 'socket_send_result') {
    const pending = socketRequests.get(packet.requestId);
    if (!pending) {
      return;
    }

    socketRequests.delete(packet.requestId);
    pending(packet);
    return;
  }

  if (packet.channel === 'db:response') {
    const pending = dbRequests.get(packet.requestId);
    if (!pending) {
      return;
    }

    dbRequests.delete(packet.requestId);

    if (packet.ok) {
      pending.resolve(packet);
    } else {
      pending.reject(new Error(packet.error || 'DB request failed'));
    }
    return;
  }

  if (packet.channel === 'route_result') {
    const pending = routeRequests.get(packet.routeId);
    if (!pending) {
      return;
    }

    routeRequests.delete(packet.routeId);

    sendToSocket(pending.connectionId, {
      type: 'sent_ack',
      id: pending.message.id,
      to: pending.message.to,
      ok: packet.ok,
      delivery: packet.delivery,
      error: packet.error || null,
    }).catch(() => {});
    return;
  }

  if (packet.channel === 'deliver_live') {
    deliverLive(packet.deliveryId, packet.message);
    return;
  }

  if (packet.channel === 'close_client') {
    const connectionId = activeClients.get(packet.name);
    if (connectionId) {
      process.send({
        channel: 'close_socket',
        connectionId,
        reason: 'same client connected on another worker',
      });
    }
  }
}

process.on('message', handlePrimaryMessage);
process.on('SIGTERM', () => process.exit(0));

console.log(`[server ${process.pid}] worker is ready`);
