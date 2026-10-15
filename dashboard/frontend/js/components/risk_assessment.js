/**
 * Risk Assessment & Dual AI Pipeline Component
 * ============================================
 * Hiển thị phán quyết mô hình kép:
 * 1. Gauge Score & Mô tả cấp độ đe dọa.
 * 2. Phán quyết on-device Edge TinyML (ESP32).
 * 3. Phân phối xác suất 15 lớp tấn công từ Host ML Engine.
 */

import { eventBus, state } from "../state.js";
import { audioService } from "../services/audio_service.js";

export const MALWARE_FAMILIES = new Set([
  "Cridex", "Geodo", "Htbot", "Miuref", "Neris", "Nsis-ay", "Shifu", "Tinba", "Virut", "Zeus"
]);

export function probabilityEntries(data, selectedClass) {
  if (data.inference_status === "unavailable") return [];
  const entries = Object.entries(data.top_probabilities || {});
  const probability = data.class_probabilities?.[selectedClass];
  if (selectedClass && Number.isFinite(probability) && !entries.some(([label]) => label === selectedClass)) {
    entries.push([selectedClass, probability * 100]);
  }
  return entries;
}

export class RiskAssessmentComponent {
  constructor() {
    this.elScoreNumber = document.getElementById("gauge-score-number");
    this.elThreatDesc = document.getElementById("gauge-threat-desc");
    this.elEdgeBadge = document.getElementById("edge-inference-badge");
    this.elEdgeModelInfo = document.getElementById("edge-model-info");
    this.elHostModelInfo = document.getElementById("host-model-info");
    this.elProbBarsList = document.getElementById("prob-bars-list");

    this.initEventListeners();
    this.fetchSystemModels();
  }

  initEventListeners() {
    eventBus.on("telemetryReceived", (data) => this.render(data));
    eventBus.on("initialStateLoaded", (stateObj) => {
      if (stateObj && stateObj.system_models) {
        this.updateModelLabels(stateObj.system_models);
      }
    });
    eventBus.on("trafficModeUpdated", () => {
      this.fetchSystemModels();
    });
  }

  async fetchSystemModels() {
    try {
      const res = await fetch("/api/system/models");
      if (res.ok) {
        const data = await res.json();
        this.updateModelLabels(data);
      }
    } catch (e) {
      // Ignored
    }
  }

  updateModelLabels(models) {
    if (!models) return;
    const clf = models.classifier || "Host ML";
    const ano = models.anomaly_detector || "Anomaly Detector";
    const feats = models.features_count || (state.trafficMode === "encrypted" ? 10 : 56);
    const isEncrypted = models.traffic_mode === "encrypted" || state.trafficMode === "encrypted" || feats === 10;
    const domainName = isEncrypted ? (models.dataset_name || "USTC-TFC2016") : (models.dataset_name || "Edge-IIoTset");
    let edge = models.edge_model || "Edge TinyML";

    if (edge === "C-Tree" || edge.includes("C-Tree") || !edge) {
      const isDl = (clf === "pytorch_deep" || clf === "dnn" || ano === "deep_autoencoder" || ano === "autoencoder");
      edge = isDl ? "EdgeDeepNet + AutoencoderNet (TFLite)" : `${clf} + ${ano} (TinyML C)`;
    }

    if (this.elEdgeModelInfo) {
      const domainDesc = isEncrypted ? `${domainName} L2-4 • Mã Hóa` : `${domainName} • Giải Mã`;
      this.elEdgeModelInfo.innerHTML = `<span style="font-weight: 600; color: var(--text-primary);">${edge}</span> (${feats} đặc trưng &bull; ${domainDesc}) &bull; Suy luận tức thời trên chip`;
    }
    if (this.elHostModelInfo) {
      const domainDesc = isEncrypted ? "10 họ mã độc • L2-4" : "15 lớp tấn công L7";
      this.elHostModelInfo.innerHTML = `<span style="font-weight: 600; color: var(--text-primary);">${clf}</span> (${feats} đặc trưng &bull; ${domainDesc}) &bull; predict_proba`;
    }
    const elAnoTitle = document.getElementById("anomaly-model-title");
    if (elAnoTitle) {
      elAnoTitle.innerText = isEncrypted ? `${ano} (Header L2-4)` : ano;
    }
    const elPipeline = document.getElementById("pipeline-ml-label");
    if (elPipeline) {
      elPipeline.innerHTML = `${ano} &bull; ${clf} (${isEncrypted ? "USTC-TFC2016" : "Edge-IIoTset"})`;
    }
  }

  render(data) {
    const inferenceAvailable = data.inference_status !== "unavailable" && Number.isFinite(data.anomaly_score);
    const score = Number(data.anomaly_score || 0);
    const threshold = data.inference_source === "esp32" && Number.isFinite(data.edge_threshold)
      ? data.edge_threshold : Number(state.anomalyThreshold || 0.55);
    const isExceeded = (score >= threshold);

    // Cập nhật điểm rủi ro: TÔN TRỌNG NGƯỠNG DO USER KÉO THANH
    if (this.elScoreNumber) {
      this.elScoreNumber.innerText = inferenceAvailable ? score.toFixed(2) : "N/A";
      if (!inferenceAvailable) {
        this.elScoreNumber.style.color = "var(--text-muted)";
      } else if (isExceeded) {
        this.elScoreNumber.style.color = "var(--crimson-danger)";
      } else if (score >= threshold * 0.8) {
        this.elScoreNumber.style.color = "var(--gold-warning)";
      } else {
        this.elScoreNumber.style.color = "var(--emerald-safe)";
      }
    }

    // Mô tả đe dọa: CHỈ BÁO ĐỎ KHI ANOMALY SCORE VƯỢT NGƯỠNG USER KÉO
    if (this.elThreatDesc) {
      if (!inferenceAvailable) {
        this.elThreatDesc.innerText = "Chưa thể suy luận: dữ liệu thiếu hoặc không tương thích với mô hình.";
        audioService.stopAlarm();
      } else if (isExceeded && data.threat_type && data.threat_type !== "Normal") {
        const isMalware = MALWARE_FAMILIES.has(data.threat_type);
        const alertPrefix = isMalware ? "[CẢNH BÁO MÃ ĐỘC]" : "[CẢNH BÁO]";
        const labelText = isMalware ? `Họ phần mềm độc hại: ${data.threat_type}` : `Phát hiện đe dọa: ${data.threat_type}`;
        this.elThreatDesc.innerHTML = `<span style="color: var(--crimson-danger); font-weight: 600;">${alertPrefix} ${labelText}</span> (${((data.confidence || 1.0) * 100).toFixed(1)}% độ tin cậy | Score: ${score.toFixed(2)} ≥ Ngưỡng: ${threshold.toFixed(2)})`;
        // Kích hoạt còi báo động qua Audio Service
        audioService.playThreatAlarm(data.severity || "HIGH");
      } else {
        this.elThreatDesc.innerHTML = `<span style="color: var(--emerald-safe); font-weight: 500;">🟢 Lưu lượng mạng bình thường. Không phát hiện rủi ro (Score: ${score.toFixed(2)} < Ngưỡng: ${threshold.toFixed(2)}).</span>`;
        // Tắt ngay lập tức còi báo động nếu trước đó đang kêu
        audioService.stopAlarm();
      }
    }

    // Phán quyết biên (TinyML trên ESP32)
    if (this.elEdgeBadge) {
      const edgePred = data.edge_prediction || "Normal";
      const isMalware = MALWARE_FAMILIES.has(edgePred);
      this.elEdgeBadge.innerText = isMalware ? `🦠 ${edgePred}` : edgePred;
      if (data.edge_inference_status === "unavailable") {
        this.elEdgeBadge.innerText = "N/A";
        this.elEdgeBadge.style.background = "rgba(148, 163, 184, 0.15)";
        this.elEdgeBadge.style.color = "var(--text-muted)";
        this.elEdgeBadge.style.borderColor = "rgba(148, 163, 184, 0.3)";
      } else if (edgePred === "Normal") {
        this.elEdgeBadge.style.background = "rgba(16, 185, 129, 0.15)";
        this.elEdgeBadge.style.color = "var(--emerald-safe)";
        this.elEdgeBadge.style.borderColor = "rgba(16, 185, 129, 0.3)";
      } else {
        this.elEdgeBadge.style.background = "rgba(239, 68, 68, 0.15)";
        this.elEdgeBadge.style.color = "var(--crimson-danger)";
        this.elEdgeBadge.style.borderColor = "rgba(239, 68, 68, 0.3)";
      }
    }

    // Cập nhật nhãn thông tin mô hình Edge TinyML & Host ML thích ứng động
    if (this.elEdgeModelInfo) {
      let edgeModel = data.edge_model || (data.raw_telemetry && data.raw_telemetry.edge_model) || "Edge TinyML";
      let edgeFeats = Number(data.edge_features_count || (data.raw_telemetry && data.raw_telemetry.edge_features_count) || (state.trafficMode === "encrypted" ? 10 : 56));
      
      // Sửa lỗi chip ESP32 nạp firmware cũ gửi C-Tree (0 đặc trưng)
      if (edgeModel === "C-Tree" || edgeFeats === 0) {
        if (data.host_classifier === "pytorch_deep" || data.host_anomaly_detector === "deep_autoencoder") {
          edgeModel = "EdgeDeepNet + AutoencoderNet (TFLite)";
          edgeFeats = 56;
        } else {
          edgeModel = `${data.host_classifier || "DecisionTree"} + ${data.host_anomaly_detector || "IsolationForest"}`;
          edgeFeats = state.trafficMode === "encrypted" ? 10 : 56;
        }
      }
      this.elEdgeModelInfo.innerHTML = `<span style="font-weight: 600; color: var(--text-primary);">${edgeModel}</span> (${edgeFeats} đặc trưng) &bull; Suy luận tức thời trên chip`;
      if (data.edge_inference_status === "unavailable") {
        this.elEdgeModelInfo.innerText = "Suy luận trên chip chưa khả dụng — cần mô hình phù hợp dữ liệu radio";
      }
    }

    if (this.elHostModelInfo) {
      const hostClf = data.host_classifier || "Host ML";
      const hostFeats = data.host_features_count || (state.trafficMode === "encrypted" ? 10 : 56);
      this.elHostModelInfo.innerHTML = `<span style="font-weight: 600; color: var(--text-primary);">${hostClf}</span> (${hostFeats} đặc trưng) &bull; predict_proba`;
      if (data.inference_source === "esp32") {
        this.elHostModelInfo.innerText = `Xác suất từ ESP32 (${data.edge_features_count || 10} đặc trưng); host chuyển tiếp kết quả`;
      }
    }

    // Cập nhật tiêu đề biểu đồ Anomaly Score theo đúng tên mô hình đang chạy
    const elAnoTitle = document.getElementById("anomaly-model-title");
    if (elAnoTitle && data.host_anomaly_detector) {
      elAnoTitle.innerText = data.inference_source === "esp32" ? "ESP32 IsolationForest (L2-4)" : data.host_anomaly_detector;
    }

    // Cập nhật node ML Engine trong sơ đồ luồng dữ liệu
    const elPipeline = document.getElementById("pipeline-ml-label");
    if (elPipeline) {
      const edgeParts = (data.edge_model && data.edge_model !== "unavailable") ? data.edge_model.split(" + ") : [];
      const edgeClf = edgeParts[0] || state.systemModels?.classifier_type || (data.host_classifier && data.host_classifier !== "not_used" ? data.host_classifier : "DecisionTree");
      const edgeAno = edgeParts[1] || state.systemModels?.anomaly_detector_type || (data.host_anomaly_detector && data.host_anomaly_detector !== "not_used" ? data.host_anomaly_detector : "IsolationForest");

      const anoName = data.inference_source === "esp32" ? `ESP32 ${edgeAno}` : data.host_anomaly_detector || "Autoencoder";
      const clfName = data.inference_source === "esp32" ? `ESP32 ${edgeClf}` : data.host_classifier || "PyTorch Deep";
      elPipeline.innerHTML = `${anoName} &bull; ${clfName}`;
    }

    // Danh sách phân phối xác suất các lớp tấn công (Host ML Engine)
    if (this.elProbBarsList) {
      const entries = probabilityEntries(data, state.experimentStatus?.scenario);
      // Sắp xếp xác suất từ cao xuống thấp
      entries.sort((a, b) => Number(b[1]) - Number(a[1]));

      if (entries.length === 0) {
        const message = data.inference_status === "unavailable"
          ? "N/A — dữ liệu không đủ hoặc không tương thích với mô hình"
          : "Chờ dữ liệu phân phối xác suất...";
        this.elProbBarsList.innerHTML = `<div style="font-size: 11px; color: var(--text-muted); text-align: center; padding: 6px 0;">${message}</div>`;
        return;
      }

      this.elProbBarsList.innerHTML = entries
        .map(([clsName, probVal]) => {
          const pct = Math.min(100, Math.max(0, Number(probVal)));
          const isDanger = clsName !== "Normal";
          const isMalware = MALWARE_FAMILIES.has(clsName);
          const barColor = isDanger ? "var(--crimson-danger)" : "var(--cyan-neon)";
          const displayName = isMalware ? `🦠 ${clsName}` : clsName;
          return `
            <div style="display: flex; flex-direction: column; gap: 2px;">
              <div style="display: flex; justify-content: space-between; font-size: 10.5px; font-family: var(--font-mono);">
                <span style="color: ${isDanger ? "var(--text-primary)" : "var(--cyan-neon)"}; font-weight: ${isDanger ? "600" : "400"};">${displayName}</span>
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
