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
  currentAnomalyScore: null,
  currentThreatLevel: "UNKNOWN",
  anomalyThreshold: 0.55,
  connectedNodes: [],
  history: [],
  latestTrafficWindow: null,
  experimentStatus: null,
  alerts: [],
  packetFilter: "ALL", // "ALL" | "THREATS"
  audioEnabled: true,
  packetCounter: 1,
  detectedWifiNetworks: [],

  // Chế độ lưu lượng & Bộ dữ liệu (Encrypted USTC-TFC2016 L2-4 vs Decrypted Edge-IIoTset L7)
  trafficMode: "encrypted", // "encrypted" | "decrypted"
  datasetName: "USTC-TFC2016",
  profile: "esp32-l234-packet-v1",
  modelLabels: [],
  systemModels: null,

  // Trạng thái của bộ phát sinh tấn công mạng thật
  attackStatus: {
    status: "IDLE",
    scenario: "Normal",
    target_ip: "127.0.0.1",
    auto_cycle: false
  },

  // Trạng thái Digital Twin và Lịch sử phản ứng phòng thủ RL
  digitalTwinState: null,
  defenseActions: [],

  setState(partialState) {
    Object.assign(this, partialState);
    eventBus.emit("stateChanged", this);
  },

  updateWifiNetworks(networks) {
    if (!Array.isArray(networks)) return;
    this.detectedWifiNetworks = networks;
    eventBus.emit("wifiNetworksUpdated", networks);
    eventBus.emit("stateChanged", this);
  },

  setInitialState(payload) {
    if (payload.experiment_status) this.updateExperimentStatus(payload.experiment_status);
    this.totalPackets = payload.total_packets || 0;
    this.totalThreats = payload.total_threats || 0;
    this.anomalyThreshold = payload.anomaly_threshold || 0.55;
    this.connectedNodes = payload.connected_nodes || [];
    this.history = payload.history || [];
    if (payload.traffic_mode) this.trafficMode = payload.traffic_mode;
    if (payload.dataset_name) this.datasetName = payload.dataset_name;
    if (payload.profile) this.profile = payload.profile;
    if (payload.system_models) {
      this.systemModels = payload.system_models;
      if (payload.system_models.traffic_mode) this.trafficMode = payload.system_models.traffic_mode;
      if (payload.system_models.dataset_name) this.datasetName = payload.system_models.dataset_name;
      if (payload.system_models.profile) this.profile = payload.system_models.profile;
      if (payload.system_models.labels) this.modelLabels = payload.system_models.labels;
    }
    if (payload.latest_traffic_window) {
      this.addTrafficWindow(payload.latest_traffic_window, payload.total_packets);
    }
    this.alerts = payload.alerts || [];
    if (payload.detected_wifi_networks) {
      this.detectedWifiNetworks = payload.detected_wifi_networks;
      eventBus.emit("wifiNetworksUpdated", this.detectedWifiNetworks);
    }
    if (payload.attack_status) {
      this.attackStatus = Object.assign(this.attackStatus, payload.attack_status);
    }
    this.wsConnected = true;
    eventBus.emit("trafficModeUpdated", this.trafficMode);
    eventBus.emit("initialStateLoaded", this);
    eventBus.emit("attackStatusUpdated", this.attackStatus);
    eventBus.emit("stateChanged", this);
  },

  updateAttackStatus(statusObj) {
    if (!statusObj) return;
    this.attackStatus = Object.assign(this.attackStatus, statusObj);
    eventBus.emit("attackStatusUpdated", this.attackStatus);
    eventBus.emit("stateChanged", this);
  },

  updateExperimentStatus(statusObj) {
    this.experimentStatus = statusObj;
    eventBus.emit("experimentStatusUpdated", statusObj);
  },

  addTelemetry(dataPoint, totalPackets, totalThreats) {
    this.totalPackets = totalPackets !== undefined ? totalPackets : this.totalPackets + (dataPoint.packet_rate || 0);
    this.totalThreats = totalThreats !== undefined ? totalThreats : this.totalThreats;
    this.currentAnomalyScore = dataPoint.inference_status === "unavailable" ? null : (dataPoint.anomaly_score || 0.0);
    this.currentThreatLevel = dataPoint.severity || "NORMAL";

    if (dataPoint.traffic_mode && dataPoint.traffic_mode !== this.trafficMode) {
      this.trafficMode = dataPoint.traffic_mode;
      if (dataPoint.dataset_name) this.datasetName = dataPoint.dataset_name;
      if (dataPoint.profile) this.profile = dataPoint.profile;
      eventBus.emit("trafficModeUpdated", this.trafficMode);
    }

    if (dataPoint.scanned_networks && Array.isArray(dataPoint.scanned_networks) && dataPoint.scanned_networks.length > 0) {
      this.updateWifiNetworks(dataPoint.scanned_networks);
    }

    this.history.push(dataPoint);
    if (this.history.length > 100) {
      this.history.shift();
    }

    eventBus.emit("telemetryReceived", dataPoint);
    eventBus.emit("stateChanged", this);
  },

  addTrafficWindow(dataPoint, totalPackets) {
    if (!dataPoint || !Number.isFinite(dataPoint.packet_rate) || !Number.isFinite(dataPoint.byte_rate)) return;
    const previous = this.latestTrafficWindow;
    if (previous && dataPoint.timestamp && previous.timestamp === dataPoint.timestamp &&
        previous.capture_id === dataPoint.capture_id && previous.device_id === dataPoint.device_id) return;
    this.latestTrafficWindow = dataPoint;
    if (totalPackets !== undefined) this.totalPackets = totalPackets;
    eventBus.emit("trafficWindowReceived", dataPoint);
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
  },

  updateDigitalTwin(twinData) {
    if (!twinData) return;
    this.digitalTwinState = twinData;
    eventBus.emit("digitalTwinUpdated", twinData);
    eventBus.emit("stateChanged", this);
  },

  addDefenseAction(actionEvent) {
    if (!actionEvent) return;
    this.defenseActions.push(actionEvent);
    if (this.defenseActions.length > 50) {
      this.defenseActions.shift();
    }
    eventBus.emit("defenseActionReceived", actionEvent);
    eventBus.emit("stateChanged", this);
  }
};
