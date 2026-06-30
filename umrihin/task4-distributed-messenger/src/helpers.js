function parseJson(raw) {
  try {
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function sendJson(ws, payload) {
  if (!ws || ws.readyState !== 1) {
    return Promise.resolve(false);
  }

  return new Promise((resolve) => {
    ws.send(JSON.stringify(payload), (error) => {
      resolve(!error);
    });
  });
}

function sendJsonNow(ws, payload) {
  if (!ws || ws.readyState !== 1) {
    return false;
  }

  ws.send(JSON.stringify(payload), () => {});
  return true;
}

function cleanName(value) {
  return String(value || '')
    .trim()
    .replace(/[^\w.-]/g, '_')
    .slice(0, 64);
}

function randomItem(items) {
  return items[Math.floor(Math.random() * items.length)];
}

function incrementMatrix(matrix, from, to) {
  if (!matrix[from]) {
    matrix[from] = {};
  }

  matrix[from][to] = (matrix[from][to] || 0) + 1;
}

function makeMessageId(clientName, number) {
  return `${clientName}-${process.pid}-${number}`;
}

module.exports = {
  cleanName,
  incrementMatrix,
  makeMessageId,
  parseJson,
  randomItem,
  sendJson,
  sendJsonNow,
};
