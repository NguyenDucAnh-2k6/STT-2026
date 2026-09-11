/**
 * Risk Assessment & Dual AI Pipeline Component
 * ============================================
 * Hiển thị phán quyết mô hình kép:
 * 1. Gauge Score & Mô tả cấp độ đe dọa.
 * 2. Phán quyết on-device Edge TinyML (ESP32).
 * 3. Phân phối xác suất 15 lớp tấn công từ Host ML Engine.
 */

import { eventBus } from "../state.js";
import { audioService } from "../services/audio_service.js";

export class RiskAssessmentComponent {
  constructor() {
    this.elScoreNumber = document.getElementById("gauge-score-number");
    this.elThreatDesc = document.getElementById("gauge-threat-desc");
    this.elEdgeBadge = document.getElementById("edge-inference-badge");
    this.elProbBarsList = document.getElementById("prob-bars-list");

    this.initEventListeners();
  }

  initEventListeners() {
    eventBus.on("telemetryReceived", (data) => this.render(data));
  }

  render(data) {
    const score = Number(data.anomaly_score || 0);

    // Cập nhật điểm rủi ro
    if (this.elScoreNumber) {
      this.elScoreNumber.innerText = score.toFixed(2);
      if (score >= 0.75) {
        this.elScoreNumber.style.color = "var(--crimson-danger)";
      } else if (score >= 0.55) {
        this.elScoreNumber.style.color = "var(--gold-warning)";
      } else {
        this.elScoreNumber.style.color = "var(--emerald-safe)";
      }
    }

    // Mô tả đe dọa
    if (this.elThreatDesc) {
      if (data.is_anomaly) {
        this.elThreatDesc.innerHTML = `<span style="color: var(--crimson-danger); font-weight: 600;">[CẢNH BÁO] Phát hiện đe dọa: ${data.threat_type}</span> (${((data.confidence || 1.0) * 100).toFixed(1)}% độ tin cậy)`;
        // Kích hoạt còi báo động qua Audio Service
        audioService.playThreatAlarm(data.severity || "HIGH");
      } else {
        this.elThreatDesc.innerText = "Lưu lượng mạng bình thường. Không phát hiện rủi ro.";
      }
    }

    // Phán quyết biên (TinyML trên ESP32)
    if (this.elEdgeBadge) {
      const edgePred = data.edge_prediction || "Normal";
      this.elEdgeBadge.innerText = edgePred;
      if (edgePred === "Normal") {
        this.elEdgeBadge.style.background = "rgba(16, 185, 129, 0.15)";
        this.elEdgeBadge.style.color = "var(--emerald-safe)";
        this.elEdgeBadge.style.borderColor = "rgba(16, 185, 129, 0.3)";
      } else {
        this.elEdgeBadge.style.background = "rgba(239, 68, 68, 0.15)";
        this.elEdgeBadge.style.color = "var(--crimson-danger)";
        this.elEdgeBadge.style.borderColor = "rgba(239, 68, 68, 0.3)";
      }
    }

    // Danh sách phân phối xác suất các lớp tấn công (Host ML Engine)
    if (this.elProbBarsList) {
      const topProbs = data.top_probabilities || {};
      const entries = Object.entries(topProbs);

      if (entries.length === 0) {
        this.elProbBarsList.innerHTML = `<div style="font-size: 11px; color: var(--text-muted); text-align: center; padding: 6px 0;">Chờ dữ liệu phân phối xác suất...</div>`;
        return;
      }

      this.elProbBarsList.innerHTML = entries
        .map(([clsName, probVal]) => {
          const pct = Math.min(100, Math.max(0, Number(probVal)));
          const isDanger = clsName !== "Normal";
          const barColor = isDanger ? "var(--crimson-danger)" : "var(--cyan-neon)";
          return `
            <div style="display: flex; flex-direction: column; gap: 2px;">
              <div style="display: flex; justify-content: space-between; font-size: 10.5px; font-family: var(--font-mono);">
                <span style="color: ${isDanger ? "var(--text-primary)" : "var(--cyan-neon)"}; font-weight: ${isDanger ? "600" : "400"};">${clsName}</span>
                <span style="color: var(--text-secondary);">${pct.toFixed(1)}%</span>
              </div>
              <div style="width: 100%; height: 5px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow: hidden;">
                <div style="width: ${pct}%; height: 100%; background: ${barColor}; transition: width 0.3s ease;"></div>
              </div>
            </div>
          `;
        })
        .join("");
    }
  }
}
