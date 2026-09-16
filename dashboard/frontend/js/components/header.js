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

    this.initEventListeners();
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
        const kb = data.total_storage_kb || 0;
        this.dataLakeBadge.innerText = `Data Lake: ${total.toLocaleString()} rows (${kb} KB)`;
        this.dataLakeBadge.title = `Sessions: ${data.total_sessions} | Normal: ${data.normal_records.toLocaleString()} | Attacks: ${data.attack_records.toLocaleString()} | Storage: ${kb} KB`;
      }
    } catch (e) {
      // Ignore network errors during reconnection
    }
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
  }
}
