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
    eventBus.on("trafficWindowReceived", (data) => this.updateRates(data));
    eventBus.on("stateChanged", () => this.render());
  }

  updateRates(data) {
    if (this.elPacketRate && Number.isFinite(data.packet_rate)) {
      this.elPacketRate.innerText = Math.round(data.packet_rate || 0).toLocaleString();
    }

    if (this.elByteRate && Number.isFinite(data.byte_rate)) {
      const kb = ((data.byte_rate || 0) / 1024).toFixed(1);
      this.elByteRate.innerText = `${kb} KB`;
    }
  }

  updateTelemetry(data) {
    this.updateRates(data);

    if (this.elAnomalyScore) {
      this.elAnomalyScore.innerText = data.inference_status === "unavailable" ? "N/A" : Number(data.anomaly_score || 0).toFixed(2);
    }

    if (this.elThreatTag) {
      const severity = data.severity || "NORMAL";
      this.elThreatTag.innerText = severity;
      this.elThreatTag.className = `threat-status-tag threat-${severity}`;
    }

    if (this.elActiveNodeName && data.device_id) {
      this.elActiveNodeName.innerText = data.device_id;
    }

    // Cập nhật Banner cảnh báo Textual Clues (L7 DPI) hoặc Tiêu đề L2-4 (Mã hóa)
    const l7Box = document.getElementById("l7-dpi-alert-box");
    const l7Type = document.getElementById("l7-dpi-threat-type");
    const l7Badge = document.getElementById("l7-dpi-badge");
    const l7Engine = document.getElementById("l7-dpi-engine");
    const l7ClueLabel = document.getElementById("l7-dpi-clue-label");

    if (l7Box) {
      const isEncrypted = state.trafficMode === "encrypted" || data.is_encrypted;
      const score = Number(data.anomaly_score || 0);
      const threshold = Number(state.anomalyThreshold || 0.55);
      const isThreat = Boolean(data.is_anomaly && score >= threshold && data.threat_type && data.threat_type !== "Normal");

      if (data.l7_threat_detected) {
        l7Box.style.display = "flex";
        if (l7Badge) l7Badge.textContent = "🚨 L7 DPI DETECTED";
        if (l7Type) l7Type.textContent = data.l7_threat_type || "Application Attack";
        if (l7ClueLabel) l7ClueLabel.innerHTML = `Dấu vết nội dung văn bản: <code id="l7-dpi-snippet" class="mono-text" style="color: #38bdf8; background: rgba(0, 0, 0, 0.4); padding: 2px 6px; border-radius: 4px;">${data.l7_text_snippet || "Textual signature matched in payload"}</code>`;
        if (l7Engine) l7Engine.textContent = "Engine: TShark DPI";
      } else if (isEncrypted && isThreat) {
        l7Box.style.display = "flex";
        if (l7Badge) l7Badge.textContent = "🔒 MÃ HÓA L2-4 PHÁT HIỆN";
        if (l7Type) l7Type.textContent = data.threat_type || "Malware Family";
        const flags = data.tcp_flags !== undefined ? "0x" + Number(data.tcp_flags).toString(16).toUpperCase() : "N/A";
        const csum = data.tcp_checksum !== undefined ? "0x" + Number(data.tcp_checksum).toString(16).toUpperCase() : "N/A";
        const len = data.tcp_len !== undefined ? data.tcp_len : (data.packet_length || 64);
        const ack = data.tcp_ack_raw !== undefined ? Number(data.tcp_ack_raw).toLocaleString() : "0";
        if (l7ClueLabel) l7ClueLabel.innerHTML = `Đặc trưng Transport Header L2-4: <code id="l7-dpi-snippet" class="mono-text" style="color: var(--cyan-neon); background: rgba(0, 0, 0, 0.4); padding: 2px 6px; border-radius: 4px;">Len: ${len}B | Flg: ${flags} | Ack: ${ack} | Csum: ${csum}</code>`;
        if (l7Engine) l7Engine.textContent = `Engine: ${data.inference_source === "esp32" ? "ESP32 TinyML L2-4" : "Host ML L2-4"}`;
      } else {
        l7Box.style.display = "none";
      }
    }
  }

  render() {
    if (this.elTotalThreats) {
      this.elTotalThreats.innerText = state.totalThreats.toLocaleString();
    }
    if (this.elAnomalyScore && state.currentAnomalyScore !== undefined) {
      this.elAnomalyScore.innerText = state.currentAnomalyScore === null ? "N/A" : Number(state.currentAnomalyScore).toFixed(2);
    }
    if (this.elThreatTag) {
      const severity = state.currentThreatLevel || "NORMAL";
      this.elThreatTag.innerText = severity;
      this.elThreatTag.className = `threat-status-tag threat-${severity}`;
    }
  }
}
