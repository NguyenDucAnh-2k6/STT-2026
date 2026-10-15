/**
 * Packet Inspector Component (Wireshark-Style Live Capture)
 * =========================================================
 * Bảng hiển thị luồng gói tin thời gian thực với bộ lọc đa điều kiện.
 */

import { state, eventBus } from "../state.js";
import { MALWARE_FAMILIES } from "./risk_assessment.js";

export class PacketInspectorComponent {
  constructor() {
    this.tableBody = document.getElementById("packet-inspector-table-body");
    this.btnFilterAll = document.getElementById("filter-all-flows");
    this.btnFilterThreats = document.getElementById("filter-threats-only");
    this.btnClearTable = document.getElementById("btn-clear-table");
    this.thFlowMetrics = document.getElementById("th-flow-metrics");
    this.badgeInspector = document.getElementById("packet-inspector-badge");

    this.currentFilter = "ALL";
    this.packetCounter = 1;

    this.initEventListeners();
    this.updateHeaders();
  }

  initEventListeners() {
    eventBus.on("telemetryReceived", (data) => this.addPacketRow(data));
    eventBus.on("trafficModeUpdated", () => this.updateHeaders());

    if (this.btnFilterAll) {
      this.btnFilterAll.addEventListener("click", () => {
        this.currentFilter = "ALL";
        this.btnFilterAll.classList.add("active");
        if (this.btnFilterThreats) this.btnFilterThreats.classList.remove("active");
        this.applyFilter();
      });
    }

    if (this.btnFilterThreats) {
      this.btnFilterThreats.addEventListener("click", () => {
        this.currentFilter = "THREATS";
        this.btnFilterThreats.classList.add("active");
        if (this.btnFilterAll) this.btnFilterAll.classList.remove("active");
        this.applyFilter();
      });
    }

    if (this.btnClearTable) {
      this.btnClearTable.addEventListener("click", () => {
        if (this.tableBody) {
          this.tableBody.innerHTML = "";
        }
      });
    }
  }

  updateHeaders() {
    const isEncrypted = state.trafficMode === "encrypted";
    if (this.thFlowMetrics) {
      this.thFlowMetrics.innerText = isEncrypted ? "L2-4 Headers (Mã hóa)" : "8 Flow Dynamics (DPI)";
    }
    if (this.badgeInspector) {
      this.badgeInspector.innerText = isEncrypted
        ? "ESP32 Promiscuous &bull; L2-4 Header Features (Mã hóa) &bull; TCP/UDP Transport"
        : "ESP32 Sniffer / PC Probe &bull; CoAP &bull; TCP/UDP Flow Dynamics";
    }
  }

  applyFilter() {
    if (!this.tableBody) return;
    Array.from(this.tableBody.children).forEach((row) => {
      if (this.currentFilter === "ALL") {
        row.style.display = "";
      } else {
        row.style.display = row.classList.contains("row-threat") ? "" : "none";
      }
    });
  }

  addPacketRow(data) {
    if (!this.tableBody) return;

    const row = document.createElement("tr");
    const score = Number(data.anomaly_score || 0);
    const threshold = Number(state.anomalyThreshold || 0.55);
    const isThreat = Boolean(data.is_anomaly && score >= threshold && data.threat_type && data.threat_type !== "Normal");
    const isEncrypted = Boolean(state.trafficMode === "encrypted" || data.is_encrypted || data.record_kind === "packet");

    if (isThreat) {
      row.className = "row-threat";
    }

    // Thời gian
    const timeStr = new Date(data.timestamp || Date.now()).toLocaleTimeString("vi-VN", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });

    const src = `${data.src_ip || "192.168.1.100"}:${data.src_port || 80}`;
    const dst = `${data.dst_ip || "192.168.1.1"}:${data.dst_port || 80}`;
    const protocol = data.protocol || "TCP";
    const length = data.packet_length || data.tcp_len || 64;

    let flowMetrics;
    if (isEncrypted) {
      const flags = data.tcp_flags !== undefined ? "0x" + Number(data.tcp_flags).toString(16).toUpperCase() : "N/A";
      const ack = data.tcp_ack_raw !== undefined ? Number(data.tcp_ack_raw).toLocaleString() : "0";
      const csum = data.tcp_checksum !== undefined ? "0x" + Number(data.tcp_checksum).toString(16).toUpperCase() : "N/A";
      flowMetrics = `Flg:${flags} | Ack:${ack} | Csum:${csum}`;
    } else {
      flowMetrics = `Pkts/s:${Math.round(data.packet_rate || 0)} | SYN:${Number(data.syn_ratio || 0).toFixed(2)} | ACK:${Number(data.ack_ratio || 0).toFixed(2)}`;
    }

    let threatBadge = `<span class="badge-threat badge-normal">Normal</span>`;
    if (isThreat) {
      const isMalware = MALWARE_FAMILIES.has(data.threat_type);
      const icon = isMalware ? "🦠 " : "⚠️ ";
      threatBadge = `<span class="badge-threat badge-danger" title="${isMalware ? "Họ mã độc USTC-TFC2016" : "Phát hiện đe dọa"}">${icon}${data.threat_type || "Threat"} (${Number(data.anomaly_score || 0).toFixed(2)})</span>`;
    }

    const payloadInfo = data.info || (isEncrypted
      ? `🔒 Encrypted TLS/VPN (${data.inference_source === "esp32" ? "ESP32 OTA" : "Host Probe"})`
      : `Flow capture probe: ${data.device_id || "ESP32"}`);

    row.innerHTML = `
      <td class="mono-text">${this.packetCounter++}</td>
      <td class="mono-text">${timeStr}</td>
      <td class="mono-text">${src}</td>
      <td class="mono-text">${dst}</td>
      <td><span class="badge-protocol badge-${protocol.toLowerCase()}">${protocol}</span></td>
      <td class="mono-text">${length}</td>
      <td class="mono-text" style="font-size: 10.5px; color: ${isEncrypted ? "var(--cyan-neon)" : "var(--text-secondary)"};">${flowMetrics}</td>
      <td>${threatBadge}</td>
      <td style="font-size: 11px; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${payloadInfo}">${payloadInfo}</td>
    `;

    // Áp dụng bộ lọc hiện tại
    if (this.currentFilter === "THREATS" && !isThreat) {
      row.style.display = "none";
    }

    this.tableBody.prepend(row);

    // Giới hạn 120 dòng để tối ưu DOM render
    if (this.tableBody.children.length > 120) {
      this.tableBody.removeChild(this.tableBody.lastChild);
    }
  }
}
