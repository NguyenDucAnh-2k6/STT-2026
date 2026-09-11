/**
 * Control Bar Component
 * =====================
 * Cụm nút điều khiển giả lập kịch bản tấn công qua REST API.
 */

import { ApiService } from "../services/api_service.js";

export class ControlBarComponent {
  constructor() {
    this.buttons = document.querySelectorAll(".btn-attack");
    this.initEventListeners();
  }

  initEventListeners() {
    this.buttons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const attackType = btn.getAttribute("data-attack");
        if (!attackType) return;

        // Cập nhật UI nút active
        this.buttons.forEach((b) => b.classList.remove("active-scenario"));
        btn.classList.add("active-scenario");

        // Gọi REST API tới backend
        btn.style.opacity = "0.6";
        await ApiService.setSimulatorScenario(attackType);
        btn.style.opacity = "1.0";
      });
    });
  }
}
