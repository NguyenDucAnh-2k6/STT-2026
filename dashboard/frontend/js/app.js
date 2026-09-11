/**
 * Edge AI Network Anomaly Detection - Frontend Application Logic
 * Real-time WebSocket Client & Interactive Dashboard
 */

document.addEventListener("DOMContentLoaded", () => {
  // State management
  const state = {
    wsConnected: false,
    totalPackets: 0,
    totalThreats: 0,
    currentAnomalyScore: 0.0,
    currentThreatLevel: "NORMAL",
    anomalyThreshold: 0.55,
    history: [],
    alerts: [],
  };

  // DOM Elements
  const elements = {
    connectionStatus: document.getElementById("connection-status"),
    statusDot: document.getElementById("status-dot"),
    kpiPacketRate: document.getElementById("kpi-packet-rate"),
    kpiByteRate: document.getElementById("kpi-byte-rate"),
    kpiAnomalyScore: document.getElementById("kpi-anomaly-score"),
    kpiTotalThreats: document.getElementById("kpi-total-threats"),
    threatTag: document.getElementById("threat-status-tag"),
    activeNodesBadge: document.getElementById("active-nodes-badge"),
    gaugeScoreNumber: document.getElementById("gauge-score-number"),
    gaugeThreatDesc: document.getElementById("gauge-threat-desc"),
    probBarsList: document.getElementById("prob-bars-list"),
    edgeInferenceBadge: document.getElementById("edge-inference-badge"),
    btnAudioToggle: document.getElementById("btn-audio-toggle"),
    packetTableBody: document.getElementById("packet-inspector-table-body"),
    btnFilterAll: document.getElementById("filter-all-flows"),
    btnFilterThreats: document.getElementById("filter-threats-only"),
    btnClearTable: document.getElementById("btn-clear-table"),
    thresholdSlider: document.getElementById("threshold-slider"),
    thresholdValue: document.getElementById("threshold-value"),
    activeNodeName: document.getElementById("active-node-name"),
  };

  let packetCounter = 1;
  let currentFilter = "ALL";

  // -------------------------------------------------------------
  // WEB AUDIO API SYNTHESIZER (SOC SIREN / ALARM SOUNDS)
  // -------------------------------------------------------------
  let audioCtx = null;
  let audioAlarmEnabled = true;
  let lastAlarmTime = 0;

  function initAudioContext() {
    if (!audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) {
        audioCtx = new AudioContextClass();
      }
    }
    if (audioCtx && audioCtx.state === "suspended") {
      audioCtx.resume();
    }
  }

  function playThreatAlarm(severity = "HIGH") {
    if (!audioAlarmEnabled) return;
    try {
      initAudioContext();
      if (!audioCtx) return;

      const now = Date.now();
      if (now - lastAlarmTime < 1200) return; // Tránh hú quá dồn dập
      lastAlarmTime = now;

      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      if (severity === "CRITICAL") {
        // Hú còi cảnh báo khẩn cấp (Police Siren)
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1350, audioCtx.currentTime + 0.15);
        osc.frequency.exponentialRampToValueAtTime(880, audioCtx.currentTime + 0.35);
        gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.42);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.45);
      } else {
        // Tiếng beep cảnh báo nhanh
        osc.type = "sine";
        osc.frequency.setValueAtTime(750, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1050, audioCtx.currentTime + 0.12);
        gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.32);
      }
    } catch (e) {
      console.warn("Audio alarm notification failed:", e);
    }
  }

  // Khởi tạo nút Toggle Âm Thanh Còi Báo Động
  if (elements.btnAudioToggle) {
    elements.btnAudioToggle.addEventListener("click", () => {
      initAudioContext();
      audioAlarmEnabled = !audioAlarmEnabled;
      elements.btnAudioToggle.innerText = audioAlarmEnabled ? "🔊 Còi Báo Động: BẬT" : "🔇 Còi Báo Động: TẮT";
      elements.btnAudioToggle.style.background = audioAlarmEnabled ? "rgba(6, 182, 212, 0.1)" : "rgba(100, 116, 139, 0.1)";
      elements.btnAudioToggle.style.borderColor = audioAlarmEnabled ? "var(--cyan-neon)" : "var(--text-muted)";
      elements.btnAudioToggle.style.color = audioAlarmEnabled ? "var(--cyan-neon)" : "var(--text-muted)";
      if (audioAlarmEnabled) {
        playThreatAlarm("MEDIUM");
      }
    });
  }

  // Filter button handlers
  if (elements.btnFilterAll) {
    elements.btnFilterAll.addEventListener("click", () => {
      currentFilter = "ALL";
      elements.btnFilterAll.classList.add("active");
      if (elements.btnFilterThreats) elements.btnFilterThreats.classList.remove("active");
      if (elements.packetTableBody) {
        Array.from(elements.packetTableBody.children).forEach((row) => {
          row.style.display = "";
        });
      }
    });
  }

  if (elements.btnFilterThreats) {
    elements.btnFilterThreats.addEventListener("click", () => {
      currentFilter = "THREATS";
      elements.btnFilterThreats.classList.add("active");
      if (elements.btnFilterAll) elements.btnFilterAll.classList.remove("active");
      if (elements.packetTableBody) {
        Array.from(elements.packetTableBody.children).forEach((row) => {
          row.style.display = row.classList.contains("row-threat") ? "" : "none";
        });
      }
    });
  }

  if (elements.btnClearTable) {
    elements.btnClearTable.addEventListener("click", () => {
      if (elements.packetTableBody) {
        elements.packetTableBody.innerHTML = "";
      }
    });
  }

  // Chart.js instances
  let trafficRateChart = null;
  let protocolDoughnutChart = null;
  let anomalyHistoryChart = null;

  // -------------------------------------------------------------
  // INITIALIZE CHARTS (CHART.JS)
  // -------------------------------------------------------------
  function initCharts() {
    Chart.defaults.color = "#a8b8b3";
    Chart.defaults.font.family = "'IBM Plex Mono', monospace";

    // 1. Throughput Line Chart (Packet Rate & Byte Rate)
    const trafficCtx = document
      .getElementById("trafficRateChart")
      .getContext("2d");
    const gradientPackets = trafficCtx.createLinearGradient(0, 0, 0, 300);
    gradientPackets.addColorStop(0, "rgba(143, 211, 185, 0.34)");
    gradientPackets.addColorStop(1, "rgba(143, 211, 185, 0.0)");

    trafficRateChart = new Chart(trafficCtx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Packets / sec",
            data: [],
            borderColor: "#8fd3b9",
            backgroundColor: gradientPackets,
            borderWidth: 2,
            pointRadius: 2,
            pointHoverRadius: 5,
            fill: true,
            tension: 0.3,
            yAxisID: "yPackets",
          },
          {
            label: "KBytes / sec",
            data: [],
            borderColor: "#b9a7db",
            backgroundColor: "transparent",
            borderWidth: 2,
            pointRadius: 0,
            borderDash: [4, 4],
            tension: 0.3,
            yAxisID: "yBytes",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { maxTicksLimit: 8, font: { size: 10 } },
          },
          yPackets: {
            type: "linear",
            position: "left",
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            title: {
              display: true,
              text: "Pkts/s",
              color: "#8fd3b9",
              font: { size: 11 },
            },
          },
          yBytes: {
            type: "linear",
            position: "right",
            grid: { drawOnChartArea: false },
            title: {
              display: true,
              text: "KB/s",
              color: "#b9a7db",
              font: { size: 11 },
            },
          },
        },
        plugins: {
          legend: { labels: { boxWidth: 12, font: { size: 11 } } },
        },
      },
    });

    // 2. Protocol Doughnut Chart (TCP, UDP, ICMP)
    const protoCtx = document.getElementById("protocolChart").getContext("2d");
    protocolDoughnutChart = new Chart(protoCtx, {
      type: "doughnut",
      data: {
        labels: ["TCP", "UDP", "ICMP"],
        datasets: [
          {
            data: [75, 24, 1],
            backgroundColor: ["#8fd3b9", "#b9a7db", "#e9bd76"],
            borderColor: "#0c1019",
            borderWidth: 3,
            hoverOffset: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        cutout: "70%",
        plugins: {
          legend: { position: "bottom", labels: { boxWidth: 12, padding: 14 } },
        },
      },
    });

    // 3. Anomaly Score History Line Chart
    const anomalyCtx = document
      .getElementById("anomalyScoreChart")
      .getContext("2d");
    const gradientAnomaly = anomalyCtx.createLinearGradient(0, 0, 0, 200);
    gradientAnomaly.addColorStop(0, "rgba(255, 127, 114, 0.34)");
    gradientAnomaly.addColorStop(1, "rgba(168, 216, 181, 0.0)");

    anomalyHistoryChart = new Chart(anomalyCtx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Anomaly Score",
            data: [],
            borderColor: "#a8d8b5",
            backgroundColor: gradientAnomaly,
            borderWidth: 2,
            pointRadius: 2,
            fill: true,
            tension: 0.2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { maxTicksLimit: 6 },
          },
          y: {
            min: 0.0,
            max: 1.0,
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { stepSize: 0.2 },
          },
        },
        plugins: {
          legend: { display: false },
        },
      },
    });
  }

  // -------------------------------------------------------------
  // WEBSOCKET COMMUNICATION
  // -------------------------------------------------------------
  let ws = null;
  function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      state.wsConnected = true;
      updateConnectionUI(true, "CONNECTED");
    };

    ws.onclose = () => {
      state.wsConnected = false;
      updateConnectionUI(false, "RECONNECTING...");
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
      console.error("[WS] Error:", err);
      ws.close();
    };

    ws.onmessage = (event) => {
      try {
        const message = jsonParseSafe(event.data);
        handleIncomingMessage(message);
      } catch (err) {
        console.error("[WS] Parse error:", err);
      }
    };
  }

  function jsonParseSafe(str) {
    try {
      return JSON.parse(str);
    } catch {
      return {};
    }
  }

  function updateConnectionUI(connected, text) {
    if (elements.connectionStatus) {
      elements.connectionStatus.innerText = text;
    }
    if (elements.statusDot) {
      if (connected) {
        elements.statusDot.classList.remove("disconnected");
      } else {
        elements.statusDot.classList.add("disconnected");
      }
    }
  }

  // -------------------------------------------------------------
  // HANDLE WEBSOCKET MESSAGES
  // -------------------------------------------------------------
  function handleIncomingMessage(msg) {
    if (msg.type === "INITIAL_STATE") {
      state.totalPackets = msg.total_packets || 0;
      state.totalThreats = msg.total_threats || 0;
      if (msg.anomaly_threshold) {
        state.anomalyThreshold = msg.anomaly_threshold;
        if (elements.thresholdSlider)
          elements.thresholdSlider.value = msg.anomaly_threshold;
        if (elements.thresholdValue)
          elements.thresholdValue.innerText = msg.anomaly_threshold.toFixed(2);
      }
      if (msg.history && msg.history.length > 0) {
        msg.history.forEach((pt) => {
          renderPacketRow(pt);
          appendTelemetryData(pt);
        });
        updateKPIs(msg.history[msg.history.length - 1]);
      }
    } else if (msg.type === "TELEMETRY_UPDATE") {
      renderPacketRow(msg.data);
      appendTelemetryData(msg.data);
      if (msg.total_packets) state.totalPackets = msg.total_packets;
      if (msg.total_threats) state.totalThreats = msg.total_threats;
      updateKPIs(msg.data);
    } else if (msg.type === "ALERT_TRIGGERED") {
      state.totalThreats = msg.total_threats || state.totalThreats + 1;
      if (elements.kpiTotalThreats)
        elements.kpiTotalThreats.innerText = state.totalThreats;
    } else if (msg.type === "NODE_UPDATE") {
      if (elements.activeNodeName)
        elements.activeNodeName.innerText = msg.node.device_id;
      if (elements.activeNodesBadge)
        elements.activeNodesBadge.innerText = "1 Node Online";
    }
  }

  // -------------------------------------------------------------
  // UPDATE CHARTS & TELEMETRY FEEDS
  // -------------------------------------------------------------
  function appendTelemetryData(data) {
    if (!data) return;
    const ts = (!data.timestamp || data.timestamp < 1000000000000) ? Date.now() : data.timestamp;
    const timeLabel = new Date(ts).toLocaleTimeString("vi-VN", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    // 1. Update Traffic Rate Chart
    if (trafficRateChart) {
      trafficRateChart.data.labels.push(timeLabel);
      trafficRateChart.data.datasets[0].data.push(data.packet_rate);
      trafficRateChart.data.datasets[1].data.push(
        Math.round(data.byte_rate / 1024),
      );

      if (trafficRateChart.data.labels.length > 40) {
        trafficRateChart.data.labels.shift();
        trafficRateChart.data.datasets[0].data.shift();
        trafficRateChart.data.datasets[1].data.shift();
      }
      trafficRateChart.update("none");
    }

    // 2. Update Protocol Chart
    if (protocolDoughnutChart) {
      const tcpRatio = Math.max(
        0,
        1.0 - (data.udp_ratio || 0) - (data.icmp_ratio || 0),
      );
      const tcpPct = Math.round(tcpRatio * 100);
      const udpPct = Math.round((data.udp_ratio || 0) * 100);
      const icmpPct = Math.round((data.icmp_ratio || 0) * 100);
      protocolDoughnutChart.data.datasets[0].data = [tcpPct, udpPct, icmpPct];
      protocolDoughnutChart.update("none");
    }

    // 3. Update Anomaly History Chart
    if (anomalyHistoryChart) {
      anomalyHistoryChart.data.labels.push(timeLabel);
      anomalyHistoryChart.data.datasets[0].data.push(data.anomaly_score);

      // Đổi màu đường anomaly nếu phát hiện nguy hiểm
      if (data.anomaly_score >= state.anomalyThreshold) {
        anomalyHistoryChart.data.datasets[0].borderColor = "#ff7f72";
      } else {
        anomalyHistoryChart.data.datasets[0].borderColor = "#a8d8b5";
      }

      if (anomalyHistoryChart.data.labels.length > 40) {
        anomalyHistoryChart.data.labels.shift();
        anomalyHistoryChart.data.datasets[0].data.shift();
      }
      anomalyHistoryChart.update("none");
    }
  }

  function updateKPIs(data) {
    if (!data) return;

    // Packet rate & byte rate
    if (elements.kpiPacketRate)
      elements.kpiPacketRate.innerText = Math.round(data.packet_rate || 0);
    if (elements.kpiByteRate) {
      const byteRate = data.byte_rate || 0;
      if (byteRate <= 0) {
        elements.kpiByteRate.innerText = "0 KB";
      } else {
        const kbRate = byteRate / 1024;
        elements.kpiByteRate.innerText =
          kbRate > 1024
            ? (kbRate / 1024).toFixed(1) + " MB"
            : Math.round(kbRate) + " KB";
      }
    }

    // Anomaly Score
    const score = data.anomaly_score || 0.0;
    if (elements.kpiAnomalyScore)
      elements.kpiAnomalyScore.innerText = score.toFixed(2);
    if (elements.gaugeScoreNumber) {
      elements.gaugeScoreNumber.innerText = score.toFixed(2);
      if (score >= state.anomalyThreshold) {
        elements.gaugeScoreNumber.classList.add("high-risk");
      } else {
        elements.gaugeScoreNumber.classList.remove("high-risk");
      }
    }

    // Threat Tag
    if (elements.threatTag) {
      const sev = data.severity || "NORMAL";
      elements.threatTag.className = `threat-status-tag threat-${sev}`;
      elements.threatTag.innerText = data.threat_type || sev;
    }

    if (elements.gaugeThreatDesc) {
      elements.gaugeThreatDesc.innerText = data.is_anomaly
        ? `Phát hiện: ${data.threat_type} (Host Conf: ${(data.confidence * 100).toFixed(1)}%)`
        : "Lưu lượng mạng bình thường. Không phát hiện rủi ro.";
    }

    // Update Edge TinyML badge
    if (elements.edgeInferenceBadge) {
      const edgeLabel = data.edge_prediction || "Normal";
      elements.edgeInferenceBadge.innerText = edgeLabel;
      if (edgeLabel !== "Normal") {
        elements.edgeInferenceBadge.style.background = "rgba(239, 68, 68, 0.25)";
        elements.edgeInferenceBadge.style.color = "var(--crimson-danger)";
        elements.edgeInferenceBadge.style.borderColor = "rgba(239, 68, 68, 0.5)";
      } else {
        elements.edgeInferenceBadge.style.background = "rgba(16, 185, 129, 0.15)";
        elements.edgeInferenceBadge.style.color = "var(--emerald-safe)";
        elements.edgeInferenceBadge.style.borderColor = "rgba(16, 185, 129, 0.3)";
      }
    }

    // Kích hoạt còi hú cảnh báo Web Audio API khi phát hiện tấn công
    if (data.is_anomaly) {
      playThreatAlarm(data.severity || "HIGH");
    }

    // Render Probability Distribution Bars
    if (elements.probBarsList) {
      let entries = [];
      if (data.top_probabilities && typeof data.top_probabilities === "object") {
        entries = Object.entries(data.top_probabilities);
      }
      // Fallback nếu chưa có dict xác suất chi tiết
      if (entries.length === 0 && data.threat_type) {
        const topConf = data.confidence ? Math.round(data.confidence * 100) : 90;
        entries = [[data.threat_type, topConf]];
        if (data.threat_type !== "Normal") {
          entries.push(["Normal", Math.max(0, 100 - topConf)]);
        }
      }

      if (entries.length > 0) {
        elements.probBarsList.innerHTML = entries.map(([className, percent]) => {
          const isTop = (className === data.threat_type && data.is_anomaly) || (entries.length > 0 && className === entries[0][0] && data.is_anomaly);
          const barColor = isTop ? "var(--crimson-danger)" : (className === "Normal" ? "var(--emerald-safe)" : "var(--cyan-neon)");
          return `
            <div style="display: flex; flex-direction: column; gap: 2px;">
              <div style="display: flex; justify-content: space-between; font-size: 11px; font-family: var(--font-mono);">
                <span style="color: ${isTop ? 'var(--crimson-danger)' : 'var(--text-primary)'}; font-weight: ${isTop ? '700' : '400'};">
                  ${isTop ? '⚠️ ' : ''}${className}
                </span>
                <span style="color: ${barColor}; font-weight: 600;">${percent}%</span>
              </div>
              <div style="width: 100%; height: 5px; background: rgba(51, 65, 85, 0.6); border-radius: 3px; overflow: hidden;">
                <div style="width: ${Math.min(percent, 100)}%; height: 100%; background: ${barColor}; border-radius: 3px; transition: width 0.4s ease;"></div>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    if (elements.kpiTotalThreats) {
      elements.kpiTotalThreats.innerText = state.totalThreats;
    }
  }

  // -------------------------------------------------------------
  // RENDER LIVE PACKET & FLOW INSPECTOR ROW (WIRESHARK-STYLE)
  // -------------------------------------------------------------
  function renderPacketRow(data) {
    if (!elements.packetTableBody || !data) return;

    const row = document.createElement("tr");
    const rawTs = data.timestamp;
    const d = new Date((!rawTs || rawTs < 1000000000000) ? Date.now() : rawTs);
    const timeStr =
      d.toLocaleTimeString("vi-VN", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }) +
      "." +
      String(d.getMilliseconds()).padStart(3, "0");

    const noStr = String(packetCounter++).padStart(5, "0");
    const proto = (data.protocol || "CoAP").toUpperCase();
    const protoClass = `proto-${proto.toLowerCase()}`;

    const isThreat =
      data.is_anomaly || (data.threat_type && data.threat_type !== "Normal");
    if (isThreat) {
      row.classList.add("row-threat");
    }

    if (currentFilter === "THREATS" && !isThreat) {
      row.style.display = "none";
    }

    let sevBadge = `<span class="badge-threat threat-normal">&#x2714; Normal (${(data.anomaly_score || 0).toFixed(2)})</span>`;
    if (isThreat) {
      const sev =
        data.severity === "CRITICAL" ? "threat-critical" : "threat-high";
      sevBadge = `<span class="badge-threat ${sev}">&#x26A0; ${data.threat_type || "Attack"} (${(data.anomaly_score || 0.95).toFixed(2)})</span>`;
    }

    const srcPort = data.src_port ? `:${data.src_port}` : "";
    const dstPort = data.dst_port ? `:${data.dst_port}` : "";
    const srcEndpoint = `${data.src_ip || "192.168.137.149"}${srcPort}`;
    const dstEndpoint = `${data.dst_ip || "192.168.137.1"}${dstPort}`;
    const pktLen =
      data.packet_length || Math.round(data.avg_packet_size || 68);

    const dynamicsHtml = `
      <span class="flow-metric-pill">Rate: <span class="flow-metric-val">${Math.round(data.packet_rate || 0)}/s</span></span>
      <span class="flow-metric-pill">SYN: <span class="flow-metric-val">${((data.syn_ratio || 0) * 100).toFixed(0)}%</span></span>
      <span class="flow-metric-pill">ACK: <span class="flow-metric-val">${((data.ack_ratio || 0) * 100).toFixed(0)}%</span></span>
      <span class="flow-metric-pill">Ports: <span class="flow-metric-val">${data.unique_dst_ports || 1}</span></span>
    `;

    const infoText =
      data.info ||
      `${proto} Flow ${srcEndpoint} -> ${dstEndpoint} Len=${pktLen}`;

    row.innerHTML = `
      <td class="mono-text" style="color: var(--text-muted); font-size: 11px;">#${noStr}</td>
      <td class="mono-text">${timeStr}</td>
      <td class="mono-text" style="color: var(--cyan-neon);">${srcEndpoint}</td>
      <td class="mono-text" style="color: #cbd5e1;">${dstEndpoint}</td>
      <td><span class="proto-badge ${protoClass}">${proto}</span></td>
      <td class="mono-text">${pktLen} B</td>
      <td>${dynamicsHtml}</td>
      <td>${sevBadge}</td>
      <td class="mono-text" style="color: var(--text-secondary); max-width: 260px; overflow: hidden; text-overflow: ellipsis;" title="${infoText}">${infoText}</td>
    `;

    // Prepend to top of table
    elements.packetTableBody.insertBefore(
      row,
      elements.packetTableBody.firstChild,
    );

    // Keep maximum 50 rows visible
    while (elements.packetTableBody.children.length > 50) {
      elements.packetTableBody.removeChild(
        elements.packetTableBody.lastChild,
      );
    }
  }

  // -------------------------------------------------------------
  // INTERACTIVE ATTACK INJECTOR (REST API)
  // -------------------------------------------------------------
  const attackButtons = document.querySelectorAll(".btn-attack");
  attackButtons.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const attackType = btn.getAttribute("data-attack");

      // Highlight active button
      attackButtons.forEach((b) => b.classList.remove("active-scenario"));
      btn.classList.add("active-scenario");

      try {
        const response = await fetch("/api/simulator/inject", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ attack_type: attackType }),
        });
        const res = await response.json();
        console.log("[Simulator Control] Sent attack inject:", res);
      } catch (err) {
        console.error("[Simulator Control] Error injecting attack:", err);
      }
    });
  });

  // Sensitivity Threshold Slider
  if (elements.thresholdSlider) {
    elements.thresholdSlider.addEventListener("input", (e) => {
      const val = parseFloat(e.target.value);
      if (elements.thresholdValue)
        elements.thresholdValue.innerText = val.toFixed(2);
      state.anomalyThreshold = val;
    });

    elements.thresholdSlider.addEventListener("change", async (e) => {
      const val = parseFloat(e.target.value);
      try {
        await fetch("/api/settings/threshold", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ threshold: val }),
        });
      } catch (err) {
        console.error("Error setting threshold:", err);
      }
    });
  }

  // Initialize application
  initCharts();
  connectWebSocket();
});
