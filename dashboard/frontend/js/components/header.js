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

    this.initEventListeners();
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
