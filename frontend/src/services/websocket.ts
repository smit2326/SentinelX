type MessageHandler = (data: any) => void;

class WebSocketClient {
  private socket: WebSocket | null = null;
  private url: string;
  private reconnectInterval: number = 3000;
  private listeners: Map<string, Set<MessageHandler>> = new Map();
  private isExplicitlyClosed: boolean = false;

  constructor() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname === 'localhost' ? 'localhost:8000' : window.location.host;
    this.url = `${protocol}//${host}/api/v1/ws/telemetry`;
  }

  public connect() {
    this.isExplicitlyClosed = false;
    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.socket = new WebSocket(this.url);

      this.socket.onopen = () => {
        console.log('[SENTINEL-X WS] Telemetry stream connected');
        this.emit('connection_status', { connected: true });
      };

      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type) {
            this.emit(data.type, data);
          }
          this.emit('message', data);
        } catch (e) {
          // Plain text ping/pong
        }
      };

      this.socket.onclose = () => {
        console.log('[SENTINEL-X WS] Telemetry stream disconnected');
        this.emit('connection_status', { connected: false });
        if (!this.isExplicitlyClosed) {
          setTimeout(() => this.connect(), this.reconnectInterval);
        }
      };

      this.socket.onerror = (err) => {
        console.warn('[SENTINEL-X WS] Error:', err);
      };
    } catch (err) {
      console.warn('[SENTINEL-X WS] Connection error:', err);
    }
  }

  public on(event: string, handler: MessageHandler) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
  }

  public off(event: string, handler: MessageHandler) {
    if (this.listeners.has(event)) {
      this.listeners.get(event)!.delete(handler);
    }
  }

  private emit(event: string, data: any) {
    if (this.listeners.has(event)) {
      this.listeners.get(event)!.forEach((handler) => handler(data));
    }
  }

  public send(data: any) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(typeof data === 'string' ? data : JSON.stringify(data));
    }
  }

  public disconnect() {
    this.isExplicitlyClosed = true;
    if (this.socket) {
      this.socket.close();
    }
  }
}

export const wsClient = new WebSocketClient();
