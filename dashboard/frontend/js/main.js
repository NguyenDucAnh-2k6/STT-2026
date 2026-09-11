/**
 * Edge AI Network Anomaly Detection - Frontend Root Application Entrypoint
 * =======================================================================
 * Khởi tạo Reactive State, các Services và nạp toàn bộ Components.
 */

import { state } from "./state.js";
import { websocketService } from "./services/websocket_service.js";
import { HeaderComponent } from "./components/header.js";
import { KpiGridComponent } from "./components/kpi_grid.js";
import { ControlBarComponent } from "./components/control_bar.js";
import { ChartsComponent } from "./components/charts.js";
import { RiskAssessmentComponent } from "./components/risk_assessment.js";
import { PacketInspectorComponent } from "./components/packet_inspector.js";

class Application {
  constructor() {
    this.components = {};
  }

  init() {
    console.log("[AERO Frontend] Initializing component-based dashboard architecture...");

    // 1. Khởi tạo các Components
    this.components.header = new HeaderComponent();
    this.components.kpiGrid = new KpiGridComponent();
    this.components.controlBar = new ControlBarComponent();
    this.components.charts = new ChartsComponent();
    this.components.riskAssessment = new RiskAssessmentComponent();
    this.components.packetInspector = new PacketInspectorComponent();

    // 2. Kết nối WebSocket Service
    websocketService.connect();

    console.log("[AERO Frontend] All components mounted successfully.");
  }
}

// Khởi chạy khi DOM đã sẵn sàng
document.addEventListener("DOMContentLoaded", () => {
  const app = new Application();
  app.init();
  window.__AERO_APP__ = app;
});
