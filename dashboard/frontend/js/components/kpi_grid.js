/**
 * KPI Grid Component
 * ==================
 * Hiển thị 4 chỉ số thống kê chính: Packet Rate, Byte Rate, Anomaly Score, Total Threats.
 */

import { state, eventBus } from "../state.js";

export class KpiGridComponent {
  constructor() {
    this.elPacketRate = document.getElementById("kpi-packet-rate");
    this.elByteRate = document.getElementById("kpi-byte-rate");
    this.elAnomalyScore = document.getElementById("kpi-anomaly-score");
    this.elTotalThreats = document.getElementById("kpi-total-threats");
    this.elThreatTag = document.getElementById("threat-status-tag");
    this.elActiveNodeName = document.getElementById("active-node-name");

    this.initEventListeners();
  }

  initEventListeners() {
    eventBus.on("telemetryReceived", (data) => this.updateTelemetry(data));
    eventBus.on("stateChanged", () => this.render());
  }

  updateTelemetry(data) {
    if (this.elPacketRate) {
      this.elPacketRate.innerText = Math.round(data.packet_rate || 0).toLocaleString();
    }

    if (this.elByteRate) {
      const kb = ((data.byte_rate || 0) / 1024).toFixed(1);
      this.elByteRate.innerText = `${kb} KB`;
    }

    if (this.elAnomalyScore) {
      this.elAnomalyScore.innerText = Number(data.anomaly_score || 0).toFixed(2);
    }

    if (this.elThreatTag) {
      const severity = data.severity || "NORMAL";
      this.elThreatTag.innerText = severity;
      this.elThreatTag.className = `threat-status-tag threat-${severity}`;
    }

    if (this.elActiveNodeName && data.device_id) {
      this.elActiveNodeName.innerText = data.device_id;
    }
  }

  render() {
    if (this.elTotalThreats) {
      this.elTotalThreats.innerText = state.totalThreats.toLocaleString();
    }
    if (this.elAnomalyScore && state.currentAnomalyScore !== undefined) {
      this.elAnomalyScore.innerText = Number(state.currentAnomalyScore).toFixed(2);
    }
    if (this.elThreatTag) {
      const severity = state.currentThreatLevel || "NORMAL";
      this.elThreatTag.innerText = severity;
      this.elThreatTag.className = `threat-status-tag threat-${severity}`;
    }
  }
}
