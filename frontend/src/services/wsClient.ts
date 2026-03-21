// wsClient.ts — WebSocket client for live dashboard updates

type EventHandler = (data: any) => void;
const handlers = new Map<string, EventHandler[]>();
let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempts = 0;

export function connectWS() {
  if (ws && ws.readyState === WebSocket.OPEN) return;

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = protocol + '//' + window.location.host + '/ws';

  ws = new WebSocket(url);

  ws.onopen = () => {
    console.log('[WS] Connected');
    reconnectAttempts = 0;
    emit('connected', {});
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      emit(data.type, data);
      emit('*', data); // wildcard handlers
    } catch (e) {}
  };

  ws.onclose = () => {
    console.log('[WS] Disconnected — reconnecting...');
    emit('disconnected', {});
    scheduleReconnect();
  };

  ws.onerror = () => {
    ws?.close();
  };
}

function scheduleReconnect() {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
  reconnectAttempts++;
  reconnectTimer = setTimeout(connectWS, delay);
}

function emit(type: string, data: any) {
  const hs = handlers.get(type) || [];
  hs.forEach(h => h(data));
}

export function onWS(type: string, handler: EventHandler) {
  if (!handlers.has(type)) handlers.set(type, []);
  handlers.get(type)!.push(handler);
  return () => {
    const hs = handlers.get(type) || [];
    handlers.set(type, hs.filter(h => h !== handler));
  };
}

export function getWSState(): 'connected' | 'disconnected' | 'connecting' {
  if (!ws) return 'disconnected';
  if (ws.readyState === WebSocket.OPEN) return 'connected';
  if (ws.readyState === WebSocket.CONNECTING) return 'connecting';
  return 'disconnected';
}
