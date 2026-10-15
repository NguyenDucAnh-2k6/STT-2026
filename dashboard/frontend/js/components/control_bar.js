/**
 * Control Bar Component
 * =====================
 * Điều khiển workload và capture Twin qua REST API và WebSocket.
 */

import { ApiService } from "../services/api_service.js";
import { eventBus, state } from "../state.js";

export class ControlBarComponent {
  constructor() {
    this.buttons = document.querySelectorAll(".btn-attack");
    this.btnAutoCycle = document.getElementById("btn-auto-cycle");
    this.statusBadge = document.getElementById("attack-status-display");
    this.targetBadge = document.getElementById("attack-target-display");
    this.tabEncrypted = document.getElementById("tab-btn-encrypted-scenarios");
    this.tabDecrypted = document.getElementById("tab-btn-decrypted-scenarios");
    this.groupEncrypted = document.getElementById("encrypted-scenarios-group");
    this.groupDecrypted = document.getElementById("decrypted-scenarios-group");
    this.controlDomainBadge = document.getElementById("control-domain-badge");

    this.pendingCommand = null;
    this.pendingTimer = null;
    this.sending = false;
    this.commandError = false;
    this.polling = false;

    this.initEventListeners();
    this.initStatusListener();
    this.syncTrafficModeTabs();
    setInterval(() => this.renderCurrentStatus(), 2000);
    setInterval(() => this.refreshExperimentStatus(), 5000);
    this.refreshExperimentStatus();
  }

  syncTrafficModeTabs() {
    const isEncrypted = state.trafficMode === "encrypted";
    if (this.groupEncrypted && this.groupDecrypted) {
      this.groupEncrypted.style.display = isEncrypted ? "flex" : "none";
      this.groupDecrypted.style.display = isEncrypted ? "none" : "flex";
    }
    if (this.tabEncrypted && this.tabDecrypted) {
      if (isEncrypted) {
        this.tabEncrypted.classList.add("active");
        this.tabEncrypted.style.borderColor = "var(--cyan-neon)";
        this.tabEncrypted.style.color = "var(--cyan-neon)";
        this.tabDecrypted.classList.remove("active");
        this.tabDecrypted.style.borderColor = "var(--border-subtle)";
        this.tabDecrypted.style.color = "var(--text-muted)";
      } else {
        this.tabDecrypted.classList.add("active");
        this.tabDecrypted.style.borderColor = "var(--purple-accent)";
        this.tabDecrypted.style.color = "var(--purple-accent)";
        this.tabEncrypted.classList.remove("active");
        this.tabEncrypted.style.borderColor = "var(--border-subtle)";
        this.tabEncrypted.style.color = "var(--text-muted)";
      }
    }
    if (this.controlDomainBadge) {
      if (isEncrypted) {
        this.controlDomainBadge.className = "badge-traffic-mode badge-traffic-encrypted";
        this.controlDomainBadge.innerHTML = `🔒 ${state.datasetName || "USTC-TFC2016"} (Mã Hóa L2-4)`;
      } else {
        this.controlDomainBadge.className = "badge-traffic-mode badge-traffic-decrypted";
        this.controlDomainBadge.innerHTML = `🔓 ${state.datasetName || "Edge-IIoTset"} (Giải Mã L7)`;
      }
    }
    this.buttons = document.querySelectorAll(".btn-attack");
  }

  async refreshExperimentStatus() {
    if (this.polling || !ApiService.getExperimentStatus) return;
    this.polling = true;
    try {
      const status = await ApiService.getExperimentStatus();
      if (status?.phase) state.updateExperimentStatus(status);
    } catch (error) {
      if (this.statusBadge) this.statusBadge.title = error.message;
    } finally {
      this.polling = false;
    }
  }

  showBadge(text, tone = "warning") {
    if (!this.statusBadge) return;
    const color = tone === "error" ? "var(--crimson-danger)" : tone === "ready" ? "var(--emerald-safe)" : "var(--amber-warning)";
    this.statusBadge.textContent = text;
    Object.assign(this.statusBadge.style, { color, borderColor: color,
      background: tone === "error" ? "rgba(255, 0, 85, 0.15)" : tone === "ready" ? "rgba(0, 255, 157, 0.12)" : "var(--amber-glow)" });
  }

  initEventListeners() {
    // Sự kiện click các nút kịch bản tấn công
    document.querySelectorAll(".btn-attack").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const attackType = btn.getAttribute("data-attack");
        if (!attackType) return;

        await this.sendCommand(btn, () => ApiService.triggerAttack(attackType));
      });
    });

    // Chuyển đổi tab Mã hóa / Giải mã thủ công
    this.tabEncrypted?.addEventListener("click", () => {
      state.trafficMode = "encrypted";
      this.syncTrafficModeTabs();
      eventBus.emit("trafficModeUpdated", "encrypted");
    });
    this.tabDecrypted?.addEventListener("click", () => {
      state.trafficMode = "decrypted";
      this.syncTrafficModeTabs();
      eventBus.emit("trafficModeUpdated", "decrypted");
    });

    eventBus.on("trafficModeUpdated", () => this.syncTrafficModeTabs());
    const stopButton = document.getElementById("btn-stop-experiment");
    stopButton?.addEventListener("click", () => this.sendCommand(stopButton, () => ApiService.stopAttack()));

    // Sự kiện nút bật/tắt Tự động xoay tua (Auto-Cycle)
    if (this.btnAutoCycle) {
      this.btnAutoCycle.addEventListener("click", async () => {
        const nextState = !state.attackStatus.auto_cycle;
        await this.sendCommand(this.btnAutoCycle, () => ApiService.toggleAutoCycle(nextState));
      });
    }
  }

  async sendCommand(btn, send) {
    if (this.sending) return;
    this.sending = true;
    this.commandError = false;
    btn.style.opacity = "0.5";
    clearTimeout(this.pendingTimer);
    this.pendingCommand = null;
    this.showBadge("⏳ Đang gửi yêu cầu thí nghiệm…");
    try {
      const result = await send();
      if (!result || result.status === "error") {
        throw new Error(result?.message || "Không gửi được lệnh; kiểm tra backend/MQTT");
      }
      if (!result.command_id) {
        throw new Error("Backend chưa hỗ trợ xác nhận lệnh; cần khởi động lại hệ thống");
      }
      this.pendingCommand = result.command_id;
      this.pendingTimer = setTimeout(() => {
        this.pendingCommand = null;
        this.commandError = true;
        this.showBadge("⚠ Phiên Twin chưa xác nhận; kiểm tra backend và tải lại trạng thái", "error");
      }, 10000);
      // An event may arrive before the REST response; preserve its later phase.
      if (result.experiment_id && result.phase && state.experimentStatus?.experiment_id !== result.experiment_id) {
        state.updateExperimentStatus(result);
      }
      this.renderCurrentStatus();
    } catch (error) {
      this.commandError = true;
      this.showBadge(`⚠ ${error.message}`, "error");
      alert(error.message);
    } finally {
      btn.style.opacity = "1.0";
      this.sending = false;
    }
  }

  initStatusListener() {
    // Lắng nghe sự kiện cập nhật trạng thái từ WebSocket
    eventBus.on("attackStatusUpdated", (attackStatus) => {
      this.renderCurrentStatus();
    });
    eventBus.on("experimentStatusUpdated", () => this.renderCurrentStatus());

    // Nếu đã có sẵn trạng thái trong state
    if (state.attackStatus) {
      this.renderCurrentStatus();
    }
  }

  renderCurrentStatus() {
    const experiment = state.experimentStatus;
    if (!experiment?.experiment_id) {
      this.renderStatus(state.attackStatus);
      return;
    }
    const active = ["STARTING", "RUNNING", "IMPORTING"].includes(experiment.phase);
    this.renderStatus({ ...experiment, status: experiment.phase === "ERROR" ? "ERROR" : active ? "ATTACKING" : "IDLE",
      expires_at_ms: Date.now() + 5000, auto_cycle: false });
    if (!this.pendingCommand && !this.commandError && this.statusBadge) {
      const counters = `Lưu ${experiment.saved_rows ?? 0} | Nhãn tự động ${experiment.labeled_rows ?? 0} | Unknown ${experiment.unknown_rows ?? 0}`;
      const liveState = (experiment.live_inference_failed ?? 0) > 0 && !(experiment.live_predictions > 0) ? "live inference lỗi/chưa sẵn sàng" :
        experiment.live_predictions > 0 ? "live inference đang nhận kết quả" : "live inference chờ kết quả";
      const captureMode = experiment.backend === "docker-raw" ? `Docker PCAP + ${liveState}` : "Đang thu PCAP";
      const text = experiment.phase === "RUNNING" ? `🟡 Đang bắn: ${experiment.scenario} — ${captureMode}` :
        experiment.phase === "STARTING" ? `⏳ Đang chuẩn bị: ${experiment.scenario}` :
        experiment.phase === "IMPORTING" ? `⏳ Đang lưu: ${experiment.scenario}` :
        experiment.phase === "ERROR" ? `⚠ ${experiment.error}` : `✓ Đã thu: ${experiment.scenario} | ${counters}`;
      this.showBadge(text, experiment.phase === "ERROR" ? "error" : active ? "warning" : "ready");
      this.statusBadge.title = `${experiment.phase} | ${counters} | Live dự đoán ${experiment.live_predictions ?? 0}, bỏ preview ${experiment.live_preview_dropped ?? 0}, lỗi ${experiment.live_inference_failed ?? 0} | ${experiment.scenario_fidelity || ""}`;
      if (experiment.supervised_training_eligible === false && experiment.phase !== "ERROR") {
        this.showBadge(text + (active ? " | Chờ kiểm chứng flow để training" : " | Không đủ bằng chứng cho supervised training"), active ? "warning" : "ready");
      }
    }
    this.buttons.forEach(button => { button.disabled = active; });
    const stopButton = document.getElementById("btn-stop-experiment");
    if (stopButton) stopButton.disabled = !["STARTING", "RUNNING"].includes(experiment.phase);
  }

  setActiveButton(scenarioName) {
    this.buttons.forEach((b) => {
      const type = b.getAttribute("data-attack");
      if (type && type.toLowerCase() === scenarioName.toLowerCase()) {
        b.classList.add("active-scenario");
      } else {
        b.classList.remove("active-scenario");
      }
    });
  }

  renderStatus(attackStatus) {
    if (!attackStatus) return;
    if (this.commandError) return;
    if (this.pendingCommand) {
      if (attackStatus.command_id !== this.pendingCommand) {
        this.showBadge("⏳ Đang chờ xác nhận áp dụng lệnh…");
        return;
      }
      clearTimeout(this.pendingTimer);
      this.pendingCommand = null;
    }
    const expired = attackStatus.status === "ATTACKING" &&
      (!Number.isFinite(attackStatus.expires_at_ms) || Date.now() > attackStatus.expires_at_ms);

    // Cập nhật target IP
    if (this.targetBadge && attackStatus.target_ip) {
      this.targetBadge.textContent = attackStatus.target_ip;
    }

    // Cập nhật text trạng thái & màu sắc
    if (this.statusBadge) {
      if (expired) {
        this.statusBadge.textContent = "⚠ Trạng thái attack đã cũ; chưa xác nhận generator đang chạy";
        this.statusBadge.style.color = "var(--text-secondary)";
      } else if (attackStatus.status === "ATTACKING") {
        this.showBadge(`🟡 Đang bắn: ${attackStatus.scenario}`);
      } else if (attackStatus.status === "UNSUPPORTED" || attackStatus.status === "ERROR") {
        this.statusBadge.textContent = `⚠ ${attackStatus.error || "Kịch bản chưa được hỗ trợ"}`;
        this.statusBadge.style.color = "var(--crimson-danger)";
      } else {
        this.statusBadge.textContent = "🟢 Sẵn sàng — chưa chạy workload";
        this.statusBadge.style.color = "var(--emerald-safe)";
        this.statusBadge.style.borderColor = "var(--emerald-safe)";
        this.statusBadge.style.background = "rgba(0, 255, 157, 0.12)";
      }
    }

    // Cập nhật nút Auto-Cycle
    if (this.btnAutoCycle) {
      if (attackStatus.auto_cycle) {
        this.btnAutoCycle.textContent = "🔄 Auto-Cycle: BẬT";
        this.btnAutoCycle.style.borderColor = "var(--purple-accent)";
        this.btnAutoCycle.style.background = "rgba(168, 85, 247, 0.25)";
      } else {
        this.btnAutoCycle.textContent = "🔄 Auto-Cycle: TẮT";
        this.btnAutoCycle.style.borderColor = "var(--border-glass)";
        this.btnAutoCycle.style.background = "rgba(255, 255, 255, 0.05)";
      }
    }

    // Đồng bộ nút active
    if (expired) {
      this.setActiveButton("");
    } else if (attackStatus.scenario) {
      this.setActiveButton(attackStatus.scenario);
    }
  }
}
