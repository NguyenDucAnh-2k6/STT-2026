/**
 * Control Bar Component
 * =====================
 * Cụm điều khiển phát động tấn công mạng thật (Raw Socket) qua REST API và WebSocket Event.
 */

import { ApiService } from "../services/api_service.js";
import { eventBus, state } from "../state.js";

export class ControlBarComponent {
  constructor() {
    this.buttons = document.querySelectorAll(".btn-attack");
    this.btnAutoCycle = document.getElementById("btn-auto-cycle");
    this.statusBadge = document.getElementById("attack-status-display");
    this.targetBadge = document.getElementById("attack-target-display");
    this.initEventListeners();
    this.initStatusListener();
  }

  initEventListeners() {
    // Sự kiện click các nút kịch bản tấn công
    this.buttons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const attackType = btn.getAttribute("data-attack");
        if (!attackType) return;

        btn.style.opacity = "0.5";

        if (attackType.toUpperCase() === "NORMAL") {
          await ApiService.stopAttack();
          this.setActiveButton("Normal");
        } else {
          await ApiService.triggerAttack(attackType);
          this.setActiveButton(attackType);
        }

        btn.style.opacity = "1.0";
      });
    });

    // Sự kiện nút bật/tắt Tự động xoay tua (Auto-Cycle)
    if (this.btnAutoCycle) {
      this.btnAutoCycle.addEventListener("click", async () => {
        const nextState = !state.attackStatus.auto_cycle;
        this.btnAutoCycle.style.opacity = "0.5";
        await ApiService.toggleAutoCycle(nextState);
        this.btnAutoCycle.style.opacity = "1.0";
      });
    }
  }

  initStatusListener() {
    // Lắng nghe sự kiện cập nhật trạng thái từ WebSocket
    eventBus.on("attackStatusUpdated", (attackStatus) => {
      this.renderStatus(attackStatus);
    });

    // Nếu đã có sẵn trạng thái trong state
    if (state.attackStatus) {
      this.renderStatus(state.attackStatus);
    }
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

    // Cập nhật target IP
    if (this.targetBadge && attackStatus.target_ip) {
      this.targetBadge.textContent = attackStatus.target_ip;
    }

    // Cập nhật text trạng thái & màu sắc
    if (this.statusBadge) {
      if (attackStatus.status === "ATTACKING") {
        this.statusBadge.textContent = `🔴 ĐANG BẮN: ${attackStatus.scenario}`;
        this.statusBadge.style.color = "var(--crimson-danger)";
        this.statusBadge.style.borderColor = "var(--crimson-danger)";
        this.statusBadge.style.background = "rgba(255, 0, 85, 0.15)";
      } else {
        this.statusBadge.textContent = "🟢 SẴN SÀNG (Lưu lượng bình thường)";
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
    if (attackStatus.scenario) {
      this.setActiveButton(attackStatus.scenario);
    }
  }
}
