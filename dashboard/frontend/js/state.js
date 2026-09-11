/**
 * Edge AI Network Anomaly Detection - Centralized Reactive State Store & Event Bus
 * ==============================================================================
 */

class EventBus {
  constructor() {
    this.events = {};
  }

  on(event, listener) {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(listener);
    return () => this.off(event, listener);
  }

  off(event, listener) {
    if (!this.events[event]) return;
    this.events[event] = this.events[event].filter((l) => l !== listener);
  }

  emit(event, data) {
    if (!this.events[event]) return;
    this.events[event].forEach((listener) => {
      try {
        listener(data);
      } catch (err) {
        console.error(`Error in event listener for '${event}':`, err);
      }
    });
  }
}

export const eventBus = new EventBus();

export const state = {
  wsConnected: false,
  totalPackets: 0,
  totalThreats: 0,
  currentAnomalyScore: 0.0,
  currentThreatLevel: "NORMAL",
  anomalyThreshold: 0.55,
  connectedNodes: [],
  history: [],
  alerts: [],
  packetFilter: "ALL", // "ALL" | "THREATS"
  audioEnabled: true,
  packetCounter: 1,

  setState(partialState) {
    Object.assign(this, partialState);
    eventBus.emit("stateChanged", this);
  },

  setInitialState(payload) {
    this.totalPackets = payload.total_packets || 0;
    this.totalThreats = payload.total_threats || 0;
    this.anomalyThreshold = payload.anomaly_threshold || 0.55;
    this.connectedNodes = payload.connected_nodes || [];
    this.history = payload.history || [];
    this.alerts = payload.alerts || [];
    this.wsConnected = true;
    eventBus.emit("initialStateLoaded", this);
    eventBus.emit("stateChanged", this);
  },

  addTelemetry(dataPoint, totalPackets, totalThreats) {
    this.totalPackets = totalPackets !== undefined ? totalPackets : this.totalPackets + (dataPoint.packet_rate || 0);
    this.totalThreats = totalThreats !== undefined ? totalThreats : this.totalThreats;
    this.currentAnomalyScore = dataPoint.anomaly_score || 0.0;
    this.currentThreatLevel = dataPoint.severity || "NORMAL";

    this.history.push(dataPoint);
    if (this.history.length > 100) {
      this.history.shift();
    }

    eventBus.emit("telemetryReceived", dataPoint);
    eventBus.emit("stateChanged", this);
  },

  addAlert(alertEntry, totalThreats) {
    this.totalThreats = totalThreats !== undefined ? totalThreats : this.totalThreats + 1;
    this.alerts.push(alertEntry);
    if (this.alerts.length > 50) {
      this.alerts.shift();
    }
    eventBus.emit("alertTriggered", alertEntry);
    eventBus.emit("stateChanged", this);
  },

  updateNode(node) {
    const idx = this.connectedNodes.findIndex((n) => n.device_id === node.device_id);
    if (idx >= 0) {
      this.connectedNodes[idx] = node;
    } else {
      this.connectedNodes.push(node);
    }
    eventBus.emit("nodeUpdated", node);
    eventBus.emit("stateChanged", this);
  }
};
