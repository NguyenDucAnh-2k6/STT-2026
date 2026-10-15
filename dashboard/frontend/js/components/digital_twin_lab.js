/**
 * Digital Twin & RL Autonomous Defense Experimentation Lab Component
 * ===================================================================
 * 1. Trực quan hóa Sơ đồ đồ thị cấu trúc mạng tương tác (Interactive Canvas Topology Graph)
 *    với các nút (Gateway, Host SOC, ESP32 Probe, IoT Sensors, Attacker, Honeypot),
 *    các luồng hạt dữ liệu thời gian thực và khiên bảo vệ Firewall/RL động.
 * 2. Đồ thị phân phối Q-Values (Chart.js) cho 6 hành động phòng thủ chuẩn NIST/MITRE D3FEND.
 * 3. Phòng thí nghiệm tương tác (Experimentation Lab):
 *    - Thử nghiệm tác tử RL (RL Policy Inference & Explainable AI XAI)
 *    - Thử nghiệm Sandbox Dry-Run (What-If Analysis)
 *    - Nhật ký sự kiện phòng thủ đóng vòng (Closed-Loop Defense Audit Log).
 */

import { state, eventBus } from "../state.js";

export class DigitalTwinLabComponent {
  constructor() {
    this.canvas = document.getElementById("twinTopologyCanvas");
    this.ctx = this.canvas ? this.canvas.getContext("2d") : null;
    this.qChart = null;
    this.animationId = null;

    // Quản lý các nút mạng trong Topology (Bố trí không gian rộng rãi, thoáng đãng)
    this.nodes = [
      {
        id: "gw_ap_01",
        label: "Gateway Router",
        sub: "AP (Ch 6)",
        ip: "192.168.1.1",
        mac: "00:1A:2B:3C:4D:01",
        role: "GATEWAY",
        x: 0.50,
        y: 0.14,
        radius: 26,
        color: "#00f0ff",
        status: "ONLINE",
        packets: 120,
        loss: 0.1
      },
      {
        id: "node_host_01",
        label: "EdgeGuard Host",
        sub: "SOC Engine",
        ip: "127.0.0.1",
        mac: "B4:2E:99:A1:00:22",
        role: "SERVER",
        x: 0.50,
        y: 0.50,
        radius: 30,
        color: "#a855f7",
        status: "ONLINE",
        packets: 450,
        loss: 0.0
      },
      {
        id: "esp32_probe_01",
        label: "ESP32 Sniffer",
        sub: "OTA 802.11 Probe",
        ip: "192.168.1.101",
        mac: "30:AE:A4:01:23:45",
        role: "PROBE",
        x: 0.16,
        y: 0.32,
        radius: 24,
        color: "#00ff9d",
        status: "ONLINE",
        packets: 300,
        loss: 0.0
      },
      {
        id: "node_iot_01",
        label: "Smart Meter",
        sub: "Benign IoT",
        ip: "192.168.1.105",
        mac: "64:E8:81:AA:BB:CC",
        role: "IOT",
        x: 0.84,
        y: 0.28,
        radius: 20,
        color: "#38bdf8",
        status: "ONLINE",
        packets: 15,
        loss: 0.2
      },
      {
        id: "node_iot_02",
        label: "Industrial Sensor",
        sub: "Modbus/MQTT",
        ip: "192.168.1.120",
        mac: "64:E8:81:DD:EE:FF",
        role: "IOT",
        x: 0.84,
        y: 0.68,
        radius: 20,
        color: "#38bdf8",
        status: "ONLINE",
        packets: 25,
        loss: 0.1
      },
      {
        id: "node_threat_01",
        label: "Rogue Attacker",
        sub: "Target of RL",
        ip: "192.168.1.199",
        mac: "DE:AD:BE:EF:AA:99",
        role: "ATTACKER",
        x: 0.16,
        y: 0.75,
        radius: 25,
        color: "#ff0055",
        status: "ATTACKING",
        packets: 3500,
        loss: 0.0,
        isMitigated: false,
        mitigationAction: null
      },
      {
        id: "node_honeypot",
        label: "Honeypot Sandbox",
        sub: "Decoy Container",
        ip: "192.168.1.250",
        mac: "02:00:DE:C0:FF:EE",
        role: "HONEYPOT",
        x: 0.50,
        y: 0.88,
        radius: 22,
        color: "#f59e0b",
        status: "STANDBY",
        packets: 0,
        loss: 0.0
      }
    ];

    // Đường liên kết mạng
    this.links = [
      { from: "gw_ap_01", to: "node_host_01", type: "core" },
      { from: "gw_ap_01", to: "node_iot_01", type: "wifi" },
      { from: "gw_ap_01", to: "node_iot_02", type: "wifi" },
      { from: "esp32_probe_01", to: "node_host_01", type: "telemetry" },
      { from: "node_threat_01", to: "node_host_01", type: "attack" },
      { from: "node_host_01", to: "node_honeypot", type: "sandbox" }
    ];

    // Hạt chuyển động trên đường truyền
    this.particles = [];
    this.initParticles();

    // Trạng thái thử nghiệm
    this.activeMitigation = null; // "BLOCK_IP_FIREWALL", "RATE_LIMIT_IP", "HONEYPOT_REDIRECT", etc.
    this.selectedNode = this.nodes.find(n => n.id === "node_threat_01");

    this.init();
  }

  init() {
    this.setupCanvasDpi();
    this.initQValuesChart();
    this.bindEvents();
    this.startAnimationLoop();
    this.fetchInitialTwinState();
  }

  setupCanvasDpi() {
    if (!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const width = rect.width || (this.canvas.parentElement ? this.canvas.parentElement.clientWidth : 900);
    const height = rect.height || 460;
    this.canvas.width = width * dpr;
    this.canvas.height = height * dpr;
    if (this.ctx) {
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
  }

  initParticles() {
    this.particles = [];
    for (let i = 0; i < 35; i++) {
      this.particles.push({
        linkIdx: i % this.links.length,
        progress: Math.random(),
        speed: 0.004 + Math.random() * 0.007,
        size: 2.5 + Math.random() * 2.0
      });
    }
  }

  initQValuesChart() {
    const ctx = document.getElementById("rlQValuesChart");
    if (!ctx) return;

    const defaultLabels = [
      "NO_ACTION",
      "RATE_LIMIT_IP",
      "BLOCK_IP_FIREWALL",
      "ISOLATE_MAC",
      "SWITCH_CH",
      "HONEYPOT"
    ];
    const defaultData = [10.0, 45.0, 135.0, 30.0, 20.0, 85.0];

    this.qChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: defaultLabels,
        datasets: [
          {
            label: "Điểm thưởng Q-Value E(s, a)",
            data: defaultData,
            backgroundColor: [
              "rgba(148, 163, 184, 0.45)",
              "rgba(245, 158, 11, 0.65)",
              "rgba(0, 255, 157, 0.85)", // Mặc định cao nhất
              "rgba(239, 68, 68, 0.55)",
              "rgba(59, 130, 246, 0.55)",
              "rgba(168, 85, 247, 0.65)"
            ],
            borderColor: [
              "#94a3b8",
              "#f59e0b",
              "#00ff9d",
              "#ef4444",
              "#3b82f6",
              "#a855f7"
            ],
            borderWidth: 1.5,
            borderRadius: 6
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(12, 16, 25, 0.95)",
            titleColor: "#00f0ff",
            bodyColor: "#f1f5f9",
            borderColor: "rgba(0, 240, 255, 0.3)",
            borderWidth: 1,
            callbacks: {
              label: (item) => ` Q(s, a) = ${item.raw.toFixed(1)} điểm thưởng RL`
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: "#94a3b8",
              font: { family: "IBM Plex Mono", size: 10 }
            }
          },
          y: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: {
              color: "#64748b",
              font: { family: "IBM Plex Mono", size: 10 }
            }
          }
        }
      }
    });
  }

  bindEvents() {
    // 1. Lắng nghe thay đổi kích thước cửa sổ
    window.addEventListener("resize", () => {
      this.setupCanvasDpi();
    });

    // 2. Click trên canvas để chọn node
    if (this.canvas) {
      this.canvas.addEventListener("click", (e) => {
        const rect = this.canvas.getBoundingClientRect();
        const clickX = e.clientX - rect.left;
        const clickY = e.clientY - rect.top;
        const width = rect.width;
        const height = rect.height;

        for (const node of this.nodes) {
          const nx = node.x * width;
          const ny = node.y * height;
          const dist = Math.hypot(clickX - nx, clickY - ny);
          if (dist <= node.radius + 6) {
            this.selectNode(node);
            break;
          }
        }
      });
    }

    // 3. Lắng nghe WebSocket sự kiện Digital Twin & Defense Action
    eventBus.on("digitalTwinUpdated", (twin) => {
      this.updateFromTwinState(twin);
    });

    eventBus.on("defenseActionReceived", (actionEvent) => {
      this.handleIncomingDefenseEvent(actionEvent);
    });

    // 4. Tab chuyển đổi giữa Đồ thị Q-Values và Sandbox Dry-Run (What-If)
    const tabQChart = document.getElementById("tab-btn-rl-chart");
    const tabDryRun = document.getElementById("tab-btn-dry-run");
    const panelQChart = document.getElementById("lab-panel-qchart");
    const panelDryRun = document.getElementById("lab-panel-dry-run");

    if (tabQChart && tabDryRun) {
      tabQChart.addEventListener("click", () => {
        tabQChart.classList.add("active");
        tabDryRun.classList.remove("active");
        if (panelQChart) panelQChart.style.display = "flex";
        if (panelDryRun) panelDryRun.style.display = "none";
      });

      tabDryRun.addEventListener("click", () => {
        tabDryRun.classList.add("active");
        tabQChart.classList.remove("active");
        if (panelQChart) panelQChart.style.display = "none";
        if (panelDryRun) panelDryRun.style.display = "flex";
      });
    }

    // 5. Nút Chọn Nhanh Mục Tiêu (Quick Target Selection)
    const btnTargetRogue = document.getElementById("btn-target-rogue");
    const btnTargetWhitelist = document.getElementById("btn-target-whitelist");
    const targetIpInput = document.getElementById("rl-test-target-ip");

    if (btnTargetRogue && targetIpInput) {
      btnTargetRogue.addEventListener("click", () => {
        targetIpInput.value = "192.168.1.199";
        const attNode = this.nodes.find(n => n.id === "node_threat_01");
        if (attNode) this.selectNode(attNode);
      });
    }

    if (btnTargetWhitelist && targetIpInput) {
      btnTargetWhitelist.addEventListener("click", () => {
        targetIpInput.value = "192.168.1.101";
        const probeNode = this.nodes.find(n => n.id === "esp32_probe_01");
        if (probeNode) this.selectNode(probeNode);
      });
    }

    // 6. Nút Thử Nghiệm Suy Luận RL Ngay
    const btnTestRl = document.getElementById("btn-test-rl-decision");
    if (btnTestRl) {
      btnTestRl.addEventListener("click", () => this.runRlEvaluation());
    }

    // 7. Nút Chạy Sandbox Dry-Run (What-If)
    const btnDryRun = document.getElementById("btn-run-sandbox-dryrun");
    if (btnDryRun) {
      btnDryRun.addEventListener("click", () => this.runDryRunSimulation());
    }

    // 8. Nút Reset trạng thái mô phỏng mạng
    const btnResetTwin = document.getElementById("btn-reset-topology-sim");
    if (btnResetTwin) {
      btnResetTwin.addEventListener("click", () => {
        this.activeMitigation = null;
        const attNode = this.nodes.find(n => n.id === "node_threat_01");
        if (attNode) {
          attNode.isMitigated = false;
          attNode.mitigationAction = null;
          attNode.status = "ATTACKING";
        }
        this.showToast("Đã khôi phục topology mạng về trạng thái mô phỏng ban đầu.", "info");
      });
    }
  }

  selectNode(node) {
    this.selectedNode = node;
    const inspectorIp = document.getElementById("inspect-node-ip");
    const inspectorRole = document.getElementById("inspect-node-role");
    const inspectorRate = document.getElementById("inspect-node-rate");
    const inspectorLoss = document.getElementById("inspect-node-loss");
    const targetIpInput = document.getElementById("rl-test-target-ip");
    const dryRunTargetInput = document.getElementById("dryrun-target-input");

    if (inspectorIp) inspectorIp.textContent = node.ip;
    if (inspectorRole) inspectorRole.textContent = `${node.label} (${node.role})`;
    if (inspectorRate) inspectorRate.textContent = `${node.packets} pkts/s`;
    if (inspectorLoss) inspectorLoss.textContent = `${(node.loss * 100).toFixed(1)}%`;
    if (targetIpInput) targetIpInput.value = node.ip;
    if (dryRunTargetInput) dryRunTargetInput.value = node.ip;
  }

  async fetchInitialTwinState() {
    try {
      const res = await fetch("/api/digital-twin/state");
      if (res.ok) {
        const data = await res.json();
        if (data.digital_twin) {
          this.updateFromTwinState(data.digital_twin);
        }
        if (Array.isArray(data.recent_defense_actions) && data.recent_defense_actions.length > 0) {
          data.recent_defense_actions.forEach(a => this.appendDefenseAuditRow(a));
        }
      }
    } catch (e) {
      console.warn("[DigitalTwinLab] Chưa thể nạp state ban đầu:", e);
    }
  }

  updateFromTwinState(twin) {
    if (!twin) return;

    // Cập nhật Airtime Gauge
    const coreCh = twin.core_channel;
    if (coreCh) {
      const airtimeEl = document.getElementById("twin-airtime-val");
      const airtimeBar = document.getElementById("twin-airtime-bar");
      const collEl = document.getElementById("twin-collision-val");

      if (airtimeEl) airtimeEl.textContent = `${coreCh.airtime_utilization}%`;
      if (airtimeBar) {
        airtimeBar.style.width = `${Math.min(100, coreCh.airtime_utilization)}%`;
        airtimeBar.style.backgroundColor = coreCh.airtime_utilization > 60 ? "var(--crimson-danger)" : "var(--cyan-neon)";
      }
      if (collEl) collEl.textContent = `${coreCh.collision_prob}%`;
    }

    // Đồng bộ các nodes nếu có
    if (Array.isArray(twin.nodes)) {
      for (const tn of twin.nodes) {
        const local = this.nodes.find(n => n.id === tn.id || n.ip === tn.ip);
        if (local) {
          local.packets = tn.rate_pkts_s || local.packets;
          local.loss = (tn.loss_pct / 100.0) || local.loss;
          if (tn.status === "ISOLATED" || tn.status === "THROTTLED") {
            local.isMitigated = true;
            local.status = tn.status;
          }
        }
      }
    }
  }

  async runRlEvaluation() {
    const scenarioSelect = document.getElementById("rl-test-scenario-select");
    const scoreInput = document.getElementById("rl-test-anomaly-slider");
    const rateInput = document.getElementById("rl-test-packet-rate");
    const targetIpInput = document.getElementById("rl-test-target-ip");
    const btn = document.getElementById("btn-test-rl-decision");

    const scenario = scenarioSelect ? scenarioSelect.value : "DDoS_TCP";
    const anomalyScore = scoreInput ? parseFloat(scoreInput.value) : 0.88;
    const packetRate = rateInput ? parseFloat(rateInput.value) : 3800;
    const targetIp = targetIpInput && targetIpInput.value.trim()
      ? targetIpInput.value.trim()
      : (this.selectedNode ? this.selectedNode.ip : "192.168.1.199");

    if (btn) {
      btn.disabled = true;
      btn.textContent = "⏳ Đang suy luận Q-Values...";
    }

    try {
      const res = await fetch("/api/digital-twin/evaluate-rl", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threat_type: scenario,
          anomaly_score: anomalyScore,
          confidence: 0.96,
          packet_rate: packetRate,
          syn_ratio: scenario === "DDoS_TCP" ? 0.92 : 0.1,
          udp_ratio: scenario === "DDoS_UDP" ? 0.90 : 0.05,
          target_ip: targetIp
        })
      });

      if (!res.ok) throw new Error("API evaluate-rl error");
      const data = await res.json();

      this.renderRlEvaluationResult(data);
    } catch (err) {
      console.error("[RL Test] Lỗi:", err);
      this.showToast("Lỗi khi kết nối tới engine đánh giá RL.", "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "⚡ Chạy Thử Nghiệm Tác Tử RL (Run RL Decision Inference)";
      }
    }
  }

  renderRlEvaluationResult(data) {
    // 1. Cập nhật biểu đồ Q-Values
    if (this.qChart && data.q_values) {
      const labels = Object.keys(data.q_values);
      const values = Object.values(data.q_values);
      const maxVal = Math.max(...values);

      const bgColors = values.map(v => (v === maxVal ? "rgba(0, 255, 157, 0.9)" : "rgba(148, 163, 184, 0.45)"));
      const borderColors = values.map(v => (v === maxVal ? "#00ff9d" : "#94a3b8"));

      this.qChart.data.labels = labels;
      this.qChart.data.datasets[0].data = values;
      this.qChart.data.datasets[0].backgroundColor = bgColors;
      this.qChart.data.datasets[0].borderColor = borderColors;
      this.qChart.update();
    }

    // 2. Cập nhật Box XAI & Decision
    const proposedEl = document.getElementById("rl-result-proposed");
    const verdictEl = document.getElementById("rl-result-action");
    const safetyEl = document.getElementById("rl-result-safety");
    const xaiEl = document.getElementById("rl-result-xai");
    const confEl = document.getElementById("rl-result-conf");

    if (proposedEl) {
      proposedEl.textContent = data.best_action || "NO_ACTION";
      proposedEl.style.color = (data.best_action === "NO_ACTION" && data.scenario !== "Normal") 
        ? "var(--amber-warning)" 
        : "var(--emerald-safe)";
    }

    if (verdictEl) {
      verdictEl.textContent = data.final_action || data.best_action;
      verdictEl.style.color = data.final_action === "NO_ACTION" ? "var(--text-muted)" : "var(--cyan-neon)";
    }

    if (safetyEl) {
      if (data.safety_verdict === "APPROVED") {
        safetyEl.textContent = "APPROVED (Phê duyệt an toàn)";
        safetyEl.style.color = "var(--emerald-safe)";
      } else {
        safetyEl.textContent = `REJECTED (${data.safety_reason || 'Bác bỏ can thiệp'})`;
        safetyEl.style.color = "var(--crimson-danger)";
      }
    }

    if (xaiEl) xaiEl.textContent = data.xai_explanation || "Đã lựa chọn hành động có giá trị kỳ vọng Bellman cao nhất.";
    if (confEl) confEl.textContent = `${data.confidence_pct}%`;

    // 3. Kích hoạt hiệu ứng phòng thủ trên Network Topology Canvas
    this.applyDefenseVisualEffect(data.final_action || data.best_action, data.target_ip);

    // 4. Thêm vào bảng Audit Log
    this.appendDefenseAuditRow({
      timestamp: Date.now() / 1000,
      target_ip: data.target_ip,
      detected_threat: data.scenario,
      proposed_action: data.best_action,
      safety_decision: data.safety_verdict,
      final_action: data.final_action,
      reason: data.safety_reason
    });

    const toastMsg = data.safety_verdict === "APPROVED"
      ? `RL Agent đề xuất: ${data.final_action} (Đã duyệt thực thi)`
      : `RL Agent đề xuất: ${data.best_action} (Safety Controller từ chối)`;
    this.showToast(toastMsg, data.safety_verdict === "APPROVED" ? "success" : "warning");
  }

  async runDryRunSimulation() {
    const actionSelect = document.getElementById("dryrun-action-select");
    const targetInput = document.getElementById("dryrun-target-input");
    const btn = document.getElementById("btn-run-sandbox-dryrun");

    const action = actionSelect ? actionSelect.value : "BLOCK_MAC";
    const target = targetInput ? targetInput.value.trim() : "192.168.1.199";

    if (btn) {
      btn.disabled = true;
      btn.textContent = "⏳ Đang chạy What-If Sandbox...";
    }

    try {
      const res = await fetch("/api/digital-twin/dry-run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: action,
          target: target,
          parameter_value: action === "RATE_LIMIT_IP" ? 25000.0 : null
        })
      });

      if (!res.ok) throw new Error("API dry-run error");
      const resData = await res.json();
      const report = resData.dry_run_report;

      if (report) {
        const suppEl = document.getElementById("dryrun-attack-suppressed");
        const collEl = document.getElementById("dryrun-collateral-damage");
        const healthEl = document.getElementById("dryrun-health-score");
        const verdictEl = document.getElementById("dryrun-verdict-badge");

        if (suppEl) suppEl.textContent = `${report.attack_suppressed_pct}%`;
        if (collEl) collEl.textContent = `${report.collateral_damage_pct}%`;
        if (healthEl) healthEl.textContent = `${(report.network_health_score * 100).toFixed(1)}%`;
        if (verdictEl) {
          verdictEl.textContent = report.verdict;
          verdictEl.className = report.recommended_to_apply ? "threat-status-tag threat-NORMAL" : "threat-status-tag threat-CRITICAL";
        }

        this.applyDefenseVisualEffect(action, target);
        this.showToast(`Dry-Run hoàn tất: Triệt tiêu ${report.attack_suppressed_pct}% tấn công!`, "success");
      }
    } catch (err) {
      console.error("[DryRun] Lỗi:", err);
      this.showToast("Lỗi khi chạy What-If Dry-Run Sandbox.", "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "🚀 Kích Hoạt Sandbox Dry-Run (What-If)";
      }
    }
  }

  applyDefenseVisualEffect(actionName, targetIp) {
    this.activeMitigation = actionName;
    const targetNode = this.nodes.find(n => n.ip === targetIp || n.id === "node_threat_01");
    if (targetNode) {
      targetNode.isMitigated = true;
      targetNode.mitigationAction = actionName;
      if (actionName.includes("BLOCK") || actionName.includes("ISOLATE")) {
        targetNode.status = "ISOLATED";
        targetNode.packets = 0;
      } else if (actionName.includes("RATE_LIMIT")) {
        targetNode.status = "THROTTLED";
        targetNode.packets = 80;
      } else if (actionName.includes("HONEYPOT")) {
        targetNode.status = "REDIRECTED";
      }
    }
  }

  handleIncomingDefenseEvent(event) {
    if (!event) return;
    this.appendDefenseAuditRow(event);
    if (event.final_action || event.proposed_action) {
      this.applyDefenseVisualEffect(event.final_action || event.proposed_action, event.target_ip);
    }
  }

  appendDefenseAuditRow(event) {
    const tbody = document.getElementById("defense-audit-table-body");
    if (!tbody) return;

    // Xóa dòng placeholder nếu có
    const placeholder = tbody.querySelector(".no-records-row");
    if (placeholder) placeholder.remove();

    const tr = document.createElement("tr");
    const d = new Date(event.timestamp ? event.timestamp * 1000 : Date.now());
    const timeStr = d.toTimeString().split(" ")[0];

    const action = event.final_action || event.enacted_action || event.proposed_action || "NO_ACTION";
    const decision = event.safety_decision || "APPROVED";
    const threat = event.detected_threat || "Threat";

    tr.innerHTML = `
      <td style="padding: 6px 10px; color: var(--text-muted);">${timeStr}</td>
      <td style="padding: 6px 10px; font-family: var(--font-mono); color: var(--cyan-neon);">${event.target_ip || '192.168.1.199'}</td>
      <td style="padding: 6px 10px; color: #f87171;">${threat}</td>
      <td style="padding: 6px 10px;"><span class="badge-edge" style="font-size: 10px; border-color: var(--emerald-safe); color: var(--emerald-safe);">${action}</span></td>
      <td style="padding: 6px 10px;"><span style="font-size: 10px; color: ${decision === 'APPROVED' ? 'var(--emerald-safe)' : 'var(--crimson-danger)'};">${decision}</span></td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);
    // Giới hạn 10 dòng
    while (tbody.children.length > 10) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  showToast(msg, type = "info") {
    // Twin notifications must not overwrite the experiment's authoritative status.
    const statusDisp = document.getElementById("twin-status-toast");
    if (statusDisp) {
      statusDisp.textContent = `🛡️ [Twin] ${msg}`;
    }
  }

  /* ==========================================================================
     VẼ ĐỒ THỊ MẠNG TRỰC QUAN TRÊN CANVAS (HTML5 ANIMATED TOPOLOGY GRAPH)
     ========================================================================== */
  startAnimationLoop() {
    const render = () => {
      this.drawTopology();
      this.animationId = requestAnimationFrame(render);
    };
    this.animationId = requestAnimationFrame(render);
  }

  drawTopology() {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    const rect = this.canvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;

    // 1. Xóa nền với hiệu ứng làm mờ nhẹ (Motion Blur trail)
    ctx.fillStyle = "rgba(7, 9, 14, 0.4)";
    ctx.fillRect(0, 0, width, height);

    // 2. Vẽ lưới tọa độ không gian số (Cyber Grid)
    this.drawCyberGrid(ctx, width, height);

    // 3. Vẽ các đường liên kết (Links)
    for (const link of this.links) {
      const fromNode = this.nodes.find(n => n.id === link.from);
      const toNode = this.nodes.find(n => n.id === link.to);
      if (!fromNode || !toNode) continue;

      const x1 = fromNode.x * width;
      const y1 = fromNode.y * height;
      const x2 = toNode.x * width;
      const y2 = toNode.y * height;

      this.drawLink(ctx, x1, y1, x2, y2, link, fromNode, toNode);
    }

    // 4. Vẽ hạt chuyển động (Moving Data / Attack Particles)
    this.drawParticles(ctx, width, height);

    // 5. Vẽ lá chắn Firewall / Biểu tượng can thiệp nếu đang có Mitigation
    this.drawMitigationShield(ctx, width, height);

    // 6. Vẽ các Nút Mạng (Nodes)
    for (const node of this.nodes) {
      const nx = node.x * width;
      const ny = node.y * height;
      this.drawNode(ctx, nx, ny, node);
    }
  }

  drawCyberGrid(ctx, width, height) {
    ctx.save();
    ctx.strokeStyle = "rgba(255, 255, 255, 0.02)";
    ctx.lineWidth = 1;
    const step = 40;
    for (let x = 0; x < width; x += step) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += step) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }
    ctx.restore();
  }

  drawLink(ctx, x1, y1, x2, y2, link, fromNode, toNode) {
    ctx.save();
    const isAttackLink = link.type === "attack";
    const isMitigated = fromNode.isMitigated || toNode.isMitigated;

    if (isAttackLink) {
      if (isMitigated) {
        // Đường bị chặn hoặc siết
        ctx.strokeStyle = "rgba(239, 68, 68, 0.25)";
        ctx.setLineDash([4, 4]);
        ctx.lineWidth = 1.5;
      } else {
        // Đang tấn công: đường phát sáng đỏ
        ctx.strokeStyle = "rgba(255, 0, 85, 0.75)";
        ctx.shadowColor = "#ff0055";
        ctx.shadowBlur = 10;
        ctx.lineWidth = 2.5;
      }
    } else if (link.type === "core") {
      ctx.strokeStyle = "rgba(168, 85, 247, 0.45)";
      ctx.lineWidth = 2;
    } else if (link.type === "sandbox") {
      ctx.strokeStyle = "rgba(245, 158, 11, 0.4)";
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1.5;
    } else {
      ctx.strokeStyle = "rgba(0, 240, 255, 0.25)";
      ctx.lineWidth = 1.5;
    }

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();
    ctx.restore();
  }

  drawParticles(ctx, width, height) {
    ctx.save();
    for (const p of this.particles) {
      p.progress += p.speed;
      if (p.progress > 1.0) p.progress = 0;

      const link = this.links[p.linkIdx];
      const fromNode = this.nodes.find(n => n.id === link.from);
      const toNode = this.nodes.find(n => n.id === link.to);
      if (!fromNode || !toNode) continue;

      let x1 = fromNode.x * width;
      let y1 = fromNode.y * height;
      let x2 = toNode.x * width;
      let y2 = toNode.y * height;

      // Nếu đang chuyển hướng Honeypot
      if (fromNode.role === "ATTACKER" && fromNode.mitigationAction === "HONEYPOT_REDIRECT") {
        const honeyNode = this.nodes.find(n => n.id === "node_honeypot");
        if (honeyNode) {
          x2 = honeyNode.x * width;
          y2 = honeyNode.y * height;
        }
      }

      // Nếu bị chặn Firewall -> hạt dừng lại ở giữa và tan biến
      if (fromNode.role === "ATTACKER" && (fromNode.mitigationAction === "BLOCK_IP_FIREWALL" || fromNode.mitigationAction === "ISOLATE_MAC_DEAUTH")) {
        if (p.progress > 0.45) continue; // Bị chặn trước khi tới Host
      }

      const px = x1 + (x2 - x1) * p.progress;
      const py = y1 + (y2 - y1) * p.progress;

      ctx.beginPath();
      ctx.arc(px, py, p.size, 0, Math.PI * 2);

      if (link.type === "attack") {
        ctx.fillStyle = fromNode.isMitigated ? "#f59e0b" : "#ff0055";
        ctx.shadowColor = ctx.fillStyle;
        ctx.shadowBlur = 8;
      } else {
        ctx.fillStyle = "#00f0ff";
        ctx.shadowColor = "#00f0ff";
        ctx.shadowBlur = 5;
      }
      ctx.fill();
    }
    ctx.restore();
  }

  drawMitigationShield(ctx, width, height) {
    const attNode = this.nodes.find(n => n.id === "node_threat_01");
    const hostNode = this.nodes.find(n => n.id === "node_host_01");
    if (!attNode || !hostNode || !attNode.isMitigated) return;

    ctx.save();
    // Tọa độ trung điểm trên đường tấn công
    const mx = (attNode.x + hostNode.x) * 0.5 * width;
    const my = (attNode.y + hostNode.y) * 0.5 * height;

    const action = attNode.mitigationAction || "BLOCK_IP_FIREWALL";

    if (action.includes("BLOCK") || action.includes("ISOLATE")) {
      // Vẽ Cyber Shield Barrier
      ctx.beginPath();
      ctx.arc(mx, my, 18, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(0, 240, 255, 0.25)";
      ctx.strokeStyle = "#00f0ff";
      ctx.lineWidth = 2;
      ctx.shadowColor = "#00f0ff";
      ctx.shadowBlur = 15;
      ctx.fill();
      ctx.stroke();

      // Icon Shield
      ctx.fillStyle = "#fff";
      ctx.font = "14px Outfit";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("🛡️", mx, my);
    } else if (action.includes("RATE_LIMIT")) {
      // Biểu tượng siết băng thông Throttling
      ctx.beginPath();
      ctx.arc(mx, my, 16, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(245, 158, 11, 0.25)";
      ctx.strokeStyle = "#f59e0b";
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#f59e0b";
      ctx.font = "10px IBM Plex Mono";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("LIMIT", mx, my);
    }
    ctx.restore();
  }

  drawNode(ctx, x, y, node) {
    ctx.save();
    const isSelected = this.selectedNode && this.selectedNode.id === node.id;

    // 1. Vòng hào quang nếu là Selected hoặc Attacker
    if (isSelected) {
      ctx.beginPath();
      ctx.arc(x, y, node.radius + 8, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(0, 240, 255, 0.7)";
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    if (node.role === "ATTACKER" && !node.isMitigated) {
      const pulse = Math.sin(Date.now() / 200) * 5;
      ctx.beginPath();
      ctx.arc(x, y, node.radius + 6 + pulse, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(255, 0, 85, 0.4)";
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // 2. Thân Node chính
    ctx.beginPath();
    ctx.arc(x, y, node.radius, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(12, 16, 25, 0.92)";
    ctx.strokeStyle = node.color;
    ctx.lineWidth = isSelected ? 2.5 : 1.8;
    ctx.shadowColor = node.color;
    ctx.shadowBlur = isSelected ? 16 : 8;
    ctx.fill();
    ctx.stroke();

    // 3. Biểu tượng vai trò
    ctx.shadowBlur = 0;
    ctx.font = "13px Outfit";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    let icon = "💻";
    if (node.role === "GATEWAY") icon = "🌐";
    else if (node.role === "SERVER") icon = "🛡️";
    else if (node.role === "PROBE") icon = "📡";
    else if (node.role === "ATTACKER") icon = node.isMitigated ? "🚫" : "🦹";
    else if (node.role === "HONEYPOT") icon = "🍯";

    ctx.fillText(icon, x, y);

    // 4. Nhãn văn bản
    ctx.font = "600 11px Outfit";
    ctx.fillStyle = "#f1f5f9";
    ctx.textAlign = "center";
    ctx.fillText(node.label, x, y + node.radius + 14);

    ctx.font = "400 9.5px IBM Plex Mono";
    ctx.fillStyle = "var(--text-muted)";
    ctx.fillText(node.ip, x, y + node.radius + 26);

    ctx.restore();
  }

  destroy() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
    }
    if (this.qChart) {
      this.qChart.destroy();
    }
  }
}
