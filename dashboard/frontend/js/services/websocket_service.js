/**
 * WebSocket Real-time Client Service
 * ==================================
 * Kết nối tới /ws/telemetry, tự động kết nối lại và đẩy tin nhắn vào State.
 */

import { state } from "../state.js";

export class WebSocketService {
  constructor() {
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectDelay = 5000;
  }

  connect() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    console.log(`[WebSocketService] Connecting to ${wsUrl}...`);
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log("[WebSocketService] Connected successfully.");
      this.reconnectAttempts = 0;
      state.setState({ wsConnected: true });
    };

    this.ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        this.handleMessage(payload);
      } catch (err) {
        console.error("[WebSocketService] Error parsing message:", err);
      }
    };

    this.ws.onclose = () => {
      console.warn("[WebSocketService] Connection closed.");
      state.setState({ wsConnected: false });
      this.scheduleReconnect();
    };

    this.ws.onerror = (err) => {
      console.error("[WebSocketService] Socket error:", err);
      this.ws.close();
    };
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), this.maxReconnectDelay);
    console.log(`[WebSocketService] Reconnecting in ${(delay / 1000).toFixed(1)}s (attempt ${this.reconnectAttempts})...`);
    setTimeout(() => this.connect(), delay);
  }

  handleMessage(payload) {
    const type = payload.type;
    if (type === "INITIAL_STATE") {
      state.setInitialState(payload);
    } else if (type === "TELEMETRY_UPDATE") {
      state.addTelemetry(payload.data, payload.total_packets, payload.total_threats);
    } else if (type === "ALERT_TRIGGERED") {
      state.addAlert(payload.alert, payload.total_threats);
    } else if (type === "NODE_UPDATE") {
      state.updateNode(payload.node);
    }
  }
}

export const websocketService = new WebSocketService();
