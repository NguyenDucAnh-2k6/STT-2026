/**
 * Packet Inspector Component (Wireshark-Style Live Capture)
 * =========================================================
 * Bảng hiển thị luồng gói tin thời gian thực với bộ lọc đa điều kiện.
 */

import { state, eventBus } from "../state.js";

export class PacketInspectorComponent {
  constructor() {
    this.tableBody = document.getElementById("packet-inspector-table-body");
    this.btnFilterAll = document.getElementById("filter-all-flows");
    this.btnFilterThreats = document.getElementById("filter-threats-only");
    this.btnClearTable = document.getElementById("btn-clear-table");

    this.currentFilter = "ALL";
    this.packetCounter = 1;

    this.initEventListeners();
  }

  initEventListeners() {
    eventBus.on("telemetryReceived", (data) => this.addPacketRow(data));

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
    const isThreat = data.is_anomaly;

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
    const length = data.packet_length || 64;

    const flowMetrics = `Pkts/s:${Math.round(data.packet_rate || 0)} | SYN:${Number(data.syn_ratio || 0).toFixed(2)} | ACK:${Number(data.ack_ratio || 0).toFixed(2)}`;

    let threatBadge = `<span class="badge-threat badge-normal">Normal</span>`;
    if (isThreat) {
      threatBadge = `<span class="badge-threat badge-danger">${data.threat_type || "Threat"} (${Number(data.anomaly_score || 0).toFixed(2)})</span>`;
    }

    const payloadInfo = data.info || `Flow capture probe: ${data.device_id || "ESP32"}`;

    row.innerHTML = `
      <td class="mono-text">${this.packetCounter++}</td>
      <td class="mono-text">${timeStr}</td>
      <td class="mono-text">${src}</td>
      <td class="mono-text">${dst}</td>
      <td><span class="badge-protocol badge-${protocol.toLowerCase()}">${protocol}</span></td>
      <td class="mono-text">${length}</td>
      <td class="mono-text" style="font-size: 10.5px; color: var(--text-secondary);">${flowMetrics}</td>
      <td>${threatBadge}</td>
      <td style="font-size: 11px; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${payloadInfo}</td>
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
