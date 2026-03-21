// wsService.js — WebSocket server for live dashboard updates
// Frontend connects once, receives real-time push when alerts detected

const WebSocket = require('ws');

let _wss = null;
const clients = new Map(); // sessionId → ws

function init(server) {
  _wss = new WebSocket.Server({ server, path: '/ws' });

  _wss.on('connection', (ws, req) => {
    const sessionId = extractSessionId(req);
    clients.set(ws, { sessionId, connectedAt: new Date() });
    console.log('[WS] Client connected, total:', clients.size);

    ws.on('close', () => {
      clients.delete(ws);
      console.log('[WS] Client disconnected, total:', clients.size);
    });

    ws.on('error', () => clients.delete(ws));

    // Send welcome + current status
    send(ws, { type: 'connected', timestamp: new Date().toISOString() });
  });

  console.log('[WS] WebSocket server ready on /ws');
  return _wss;
}

// ─── Broadcast to all connected clients ──────────────────────────────────
function broadcast(event) {
  if (!_wss) return;
  const msg = JSON.stringify(event);
  let sent = 0;
  for (const [ws] of clients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
      sent++;
    }
  }
  if (sent > 0) {
    console.log('[WS] Broadcast', event.type, 'to', sent, 'clients');
  }
}

// ─── Send to specific client ──────────────────────────────────────────────
function send(ws, event) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(event));
  }
}

// ─── Event helpers ────────────────────────────────────────────────────────
function broadcastNewAlert(alert) {
  broadcast({
    type:      'new_alert',
    alert,
    timestamp: new Date().toISOString()
  });
}

function broadcastAlertUpdate(alertId, changes) {
  broadcast({
    type:      'alert_updated',
    alertId,
    changes,
    timestamp: new Date().toISOString()
  });
}

function broadcastScanComplete(tenantId, newAlertCount) {
  broadcast({
    type:          'scan_complete',
    tenantId,
    newAlertCount,
    timestamp:     new Date().toISOString()
  });
}

function extractSessionId(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/connect\.sid=([^;]+)/);
  return match ? match[1] : 'unknown';
}

module.exports = {
  init,
  broadcast,
  broadcastNewAlert,
  broadcastAlertUpdate,
  broadcastScanComplete
};
