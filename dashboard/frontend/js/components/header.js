/**
 * Header Component
 * ================
 * Quản lý trạng thái kết nối mạng, số node online và nút toggle còi báo động.
 */

import { state, eventBus } from "../state.js";
import { audioService } from "../services/audio_service.js";

export class HeaderComponent {
  constructor() {
    this.statusDot = document.getElementById("status-dot");
    this.connectionStatus = document.getElementById("connection-status");
    this.activeNodesBadge = document.getElementById("active-nodes-badge");
    this.btnAudioToggle = document.getElementById("btn-audio-toggle");
    this.dataLakeBadge = document.getElementById("data-lake-badge");
    this.btnCloudSync = document.getElementById("btn-cloud-sync");
    this.trafficDomainBadge = document.getElementById("traffic-domain-badge");
    this.brandPill = document.getElementById("brand-traffic-mode-pill");
    this.captureHealthBadge = document.createElement("span");
    this.captureHealthBadge.id = "capture-health-badge";
    this.captureHealthBadge.className = "system-status-indicator";
    this.captureHealthBadge.textContent = "Capture: chờ bộ đếm";
    this.dataLakeBadge?.parentElement?.insertAdjacentElement("afterend", this.captureHealthBadge);
    eventBus.on("trafficWindowReceived", data => this.renderCaptureHealth(data));
    eventBus.on("trafficModeUpdated", () => this.renderTrafficDomainBadge());

    this.initEventListeners();
    this.renderTrafficDomainBadge();
    this.pollDataLake();
    setInterval(() => this.pollDataLake(), 5000);
  }

  async pollDataLake() {
    if (!this.dataLakeBadge) return;
    try {
      const res = await fetch("/api/data-lake/summary");
      if (res.ok) {
        const data = await res.json();
        const total = data.total_records || 0;
        const kb = Number(data.total_storage_kb || 0).toFixed(1);
        this.dataLakeBadge.innerText = `Data Lake: ${total.toLocaleString()} rows (${kb} KB)`;
        this.dataLakeBadge.title = `Đã ghi Parquet: ${total.toLocaleString()} | Buffer: ${data.buffered_records ?? "?"} | Phiên hiện tại: ${data.current_session_records ?? "?"} | Sessions: ${data.total_sessions}`;
      }
    } catch (e) {
      // Ignore network errors during reconnection
    }
  }

  renderCaptureHealth(data) {
    if (!Number.isFinite(data.captured_packets)) return;
    const dropped = data.dropped ?? 0;
    const percent = data.captured_packets > 0 ? 100 * dropped / data.captured_packets : 0;
    this.captureHealthBadge.textContent = `Capture: ${data.captured_packets.toLocaleString()} | Drop: ${percent.toFixed(1)}%`;
    this.captureHealthBadge.style.color = dropped > 0 ? "var(--crimson-danger)" : "var(--emerald-safe)";
    this.captureHealthBadge.title = `Phiên capture: ${data.capture_id ?? "?"} | Interface: ${(data.capture_interfaces ?? []).join(", ") || "?"} | MQTT PUBACK: ${data.published ?? "?"} | Queue drop: ${dropped} | Failed/timeout: ${data.failed ?? "?"} | Rejected: ${data.rejected_packets ?? "?"} | Queue: ${data.publish_queue_depth ?? "?"}/${data.publish_queue_capacity ?? "?"}. PUBACK chưa xác nhận đã ghi Parquet.`;
  }

  initEventListeners() {
    // Lắng nghe thay đổi trạng thái
    eventBus.on("stateChanged", () => this.render());

    // Nút toggle Audio
    if (this.btnAudioToggle) {
      this.btnAudioToggle.addEventListener("click", () => {
        audioService.initContext();
        state.audioEnabled = !state.audioEnabled;
        this.renderAudioButton();
        if (state.audioEnabled) {
          audioService.playThreatAlarm("MEDIUM");
        }
      });
    }

    // Nút Cloud Sync
    if (this.btnCloudSync) {
      this.btnCloudSync.addEventListener("click", async () => {
        this.btnCloudSync.innerText = "⏳ Đang Sync...";
        this.btnCloudSync.disabled = true;
        try {
          const res = await fetch("/api/remote-storage/push", { method: "POST" });
          const data = await res.json();
          if (data.success) {
            this.btnCloudSync.innerText = `✅ Đã Push (${data.uploaded_count || 0})`;
            this.btnCloudSync.style.borderColor = "#10b981";
            this.btnCloudSync.style.color = "#10b981";
            setTimeout(() => {
              this.btnCloudSync.innerText = "☁️ Sync R2 / Cloud";
              this.btnCloudSync.style.borderColor = "#3b82f6";
              this.btnCloudSync.style.color = "#60a5fa";
              this.btnCloudSync.disabled = false;
            }, 3000);
          } else {
            alert(`Lưu ý Remote Storage: ${data.message || "Không thể kết nối"}`);
            this.btnCloudSync.innerText = "⚠️ Chưa cấu hình";
            setTimeout(() => {
              this.btnCloudSync.innerText = "☁️ Sync R2 / Cloud";
              this.btnCloudSync.disabled = false;
            }, 3000);
          }
        } catch (e) {
          alert(`Lỗi kết nối tới Server Backend: ${e}`);
          this.btnCloudSync.innerText = "☁️ Sync R2 / Cloud";
          this.btnCloudSync.disabled = false;
        }
      });
    }
  }


  renderAudioButton() {
    if (!this.btnAudioToggle) return;
    const enabled = state.audioEnabled;
    this.btnAudioToggle.innerText = enabled ? "🔊 Còi Báo Động: BẬT" : "🔇 Còi Báo Động: TẮT";
    this.btnAudioToggle.style.background = enabled ? "rgba(6, 182, 212, 0.1)" : "rgba(100, 116, 139, 0.1)";
    this.btnAudioToggle.style.borderColor = enabled ? "var(--cyan-neon)" : "var(--text-muted)";
    this.btnAudioToggle.style.color = enabled ? "var(--cyan-neon)" : "var(--text-muted)";
  }

  renderTrafficDomainBadge() {
    if (!this.trafficDomainBadge) {
      this.trafficDomainBadge = document.getElementById("traffic-domain-badge");
    }
    if (!this.brandPill) {
      this.brandPill = document.getElementById("brand-traffic-mode-pill");
    }
    const isEncrypted = state.trafficMode === "encrypted";
    if (this.trafficDomainBadge) {
      if (isEncrypted) {
        this.trafficDomainBadge.className = "badge-traffic-mode badge-traffic-encrypted";
        this.trafficDomainBadge.innerHTML = `🔒 MÃ HÓA (${state.datasetName || "USTC-TFC2016"} • 10 L2-4)`;
        this.trafficDomainBadge.title = "Chế độ lưu lượng mã hóa: Phân tích 10 trường Header L2-4 (USTC-TFC2016), phát hiện 10 họ mã độc mà không cần giải mã L7 DPI.";
      } else {
        this.trafficDomainBadge.className = "badge-traffic-mode badge-traffic-decrypted";
        this.trafficDomainBadge.innerHTML = `🔓 GIẢI MÃ (${state.datasetName || "Edge-IIoTset"} • 56 L7)`;
        this.trafficDomainBadge.title = "Chế độ lưu lượng giải mã: Phân tích 56 đặc trưng L7 Deep Packet Inspection (Edge-IIoTset).";
      }
    }
    if (this.brandPill) {
      if (isEncrypted) {
        this.brandPill.innerText = "L2-4 ENCRYPTED";
        this.brandPill.style.color = "var(--cyan-neon)";
        this.brandPill.style.borderColor = "rgba(143, 211, 185, 0.4)";
        this.brandPill.style.background = "rgba(143, 211, 185, 0.15)";
      } else {
        this.brandPill.innerText = "L7 DECRYPTED DPI";
        this.brandPill.style.color = "var(--purple-accent)";
        this.brandPill.style.borderColor = "rgba(185, 167, 219, 0.4)";
        this.brandPill.style.background = "rgba(185, 167, 219, 0.15)";
      }
    }
  }

  render() {
    // Trạng thái kết nối WebSocket
    if (this.connectionStatus && this.statusDot) {
      if (state.wsConnected) {
        this.statusDot.className = "status-dot status-online";
        this.connectionStatus.innerText = "HE THONG TRUC TUYEN (LIVE)";
        this.connectionStatus.style.color = "var(--emerald-safe)";
      } else {
        this.statusDot.className = "status-dot status-offline";
        this.connectionStatus.innerText = "DANG KET NOI LAI...";
        this.connectionStatus.style.color = "var(--crimson-danger)";
      }
    }

    // Số node kết nối
    if (this.activeNodesBadge) {
      const count = state.connectedNodes.length || 1;
      this.activeNodesBadge.innerText = `${count} Node Online`;
    }

    this.renderAudioButton();
    this.renderTrafficDomainBadge();
  }
}
