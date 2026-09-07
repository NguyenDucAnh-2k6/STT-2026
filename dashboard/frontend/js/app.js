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
        alerts: []
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
        alertsTableBody: document.getElementById("alerts-table-body"),
        thresholdSlider: document.getElementById("threshold-slider"),
        thresholdValue: document.getElementById("threshold-value"),
        activeNodeName: document.getElementById("active-node-name")
    };

    // Chart.js instances
    let trafficRateChart = null;
    let protocolDoughnutChart = null;
    let anomalyHistoryChart = null;

    // -------------------------------------------------------------
    // INITIALIZE CHARTS (CHART.JS)
    // -------------------------------------------------------------
    function initCharts() {
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = "'JetBrains Mono', monospace";

        // 1. Throughput Line Chart (Packet Rate & Byte Rate)
        const trafficCtx = document.getElementById("trafficRateChart").getContext("2d");
        const gradientPackets = trafficCtx.createLinearGradient(0, 0, 0, 300);
        gradientPackets.addColorStop(0, "rgba(0, 240, 255, 0.35)");
        gradientPackets.addColorStop(1, "rgba(0, 240, 255, 0.0)");

        trafficRateChart = new Chart(trafficCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Packets / sec",
                        data: [],
                        borderColor: "#00f0ff",
                        backgroundColor: gradientPackets,
                        borderWidth: 2,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                        fill: true,
                        tension: 0.3,
                        yAxisID: "yPackets"
                    },
                    {
                        label: "KBytes / sec",
                        data: [],
                        borderColor: "#a855f7",
                        backgroundColor: "transparent",
                        borderWidth: 2,
                        pointRadius: 0,
                        borderDash: [4, 4],
                        tension: 0.3,
                        yAxisID: "yBytes"
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { maxTicksLimit: 8, font: { size: 10 } }
                    },
                    yPackets: {
                        type: "linear",
                        position: "left",
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        title: { display: true, text: "Pkts/s", color: "#00f0ff", font: { size: 11 } }
                    },
                    yBytes: {
                        type: "linear",
                        position: "right",
                        grid: { drawOnChartArea: false },
                        title: { display: true, text: "KB/s", color: "#a855f7", font: { size: 11 } }
                    }
                },
                plugins: {
                    legend: { labels: { boxWidth: 12, font: { size: 11 } } }
                }
            }
        });

        // 2. Protocol Doughnut Chart (TCP, UDP, ICMP)
        const protoCtx = document.getElementById("protocolChart").getContext("2d");
        protocolDoughnutChart = new Chart(protoCtx, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "ICMP"],
                datasets: [{
                    data: [75, 24, 1],
                    backgroundColor: ["#00f0ff", "#a855f7", "#ffb703"],
                    borderColor: "#0c1019",
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "70%",
                plugins: {
                    legend: { position: "bottom", labels: { boxWidth: 12, padding: 14 } }
                }
            }
        });

        // 3. Anomaly Score History Line Chart
        const anomalyCtx = document.getElementById("anomalyScoreChart").getContext("2d");
        const gradientAnomaly = anomalyCtx.createLinearGradient(0, 0, 0, 200);
        gradientAnomaly.addColorStop(0, "rgba(255, 0, 85, 0.4)");
        gradientAnomaly.addColorStop(1, "rgba(0, 255, 157, 0.0)");

        anomalyHistoryChart = new Chart(anomalyCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Anomaly Score",
                    data: [],
                    borderColor: "#00ff9d",
                    backgroundColor: gradientAnomaly,
                    borderWidth: 2,
                    pointRadius: 2,
                    fill: true,
                    tension: 0.2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                scales: {
                    x: { grid: { color: "rgba(255, 255, 255, 0.05)" }, ticks: { maxTicksLimit: 6 } },
                    y: {
                        min: 0.0,
                        max: 1.0,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { stepSize: 0.2 }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
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
                if (elements.thresholdSlider) elements.thresholdSlider.value = msg.anomaly_threshold;
                if (elements.thresholdValue) elements.thresholdValue.innerText = msg.anomaly_threshold.toFixed(2);
            }
            if (msg.alerts && msg.alerts.length > 0) {
                msg.alerts.forEach(renderAlertRow);
            }
            if (msg.history && msg.history.length > 0) {
                msg.history.forEach(appendTelemetryData);
            }
        } else if (msg.type === "TELEMETRY_UPDATE") {
            appendTelemetryData(msg.data);
            if (msg.total_packets) state.totalPackets = msg.total_packets;
            if (msg.total_threats) state.totalThreats = msg.total_threats;
            updateKPIs(msg.data);
        } else if (msg.type === "ALERT_TRIGGERED") {
            state.totalThreats = msg.total_threats || (state.totalThreats + 1);
            if (elements.kpiTotalThreats) elements.kpiTotalThreats.innerText = state.totalThreats;
            renderAlertRow(msg.alert);
        } else if (msg.type === "NODE_UPDATE") {
            if (elements.activeNodeName) elements.activeNodeName.innerText = msg.node.device_id;
            if (elements.activeNodesBadge) elements.activeNodesBadge.innerText = "1 Node Online";
        }
    }

    // -------------------------------------------------------------
    // UPDATE CHARTS & TELEMETRY FEEDS
    // -------------------------------------------------------------
    function appendTelemetryData(data) {
        if (!data) return;
        const timeLabel = new Date(data.timestamp).toLocaleTimeString("vi-VN", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });

        // 1. Update Traffic Rate Chart
        if (trafficRateChart) {
            trafficRateChart.data.labels.push(timeLabel);
            trafficRateChart.data.datasets[0].data.push(data.packet_rate);
            trafficRateChart.data.datasets[1].data.push(Math.round(data.byte_rate / 1024));

            if (trafficRateChart.data.labels.length > 30) {
                trafficRateChart.data.labels.shift();
                trafficRateChart.data.datasets[0].data.shift();
                trafficRateChart.data.datasets[1].data.shift();
            }
            trafficRateChart.update("none");
        }

        // 2. Update Protocol Chart
        if (protocolDoughnutChart) {
            const tcpRatio = Math.max(0, 1.0 - (data.udp_ratio || 0) - (data.icmp_ratio || 0));
            const tcpPct = Math.round(tcpRatio * 100);
            const udpPct = Math.round((data.udp_ratio || 0) * 100);
            const icmpPct = Math.round((data.icmp_ratio || 0) * 100);
            protocolDoughnutChart.data.datasets[0].data = [tcpPct, udpPct, icmpPct];
            protocolDoughnutChart.update();
        }

        // 3. Update Anomaly History Chart
        if (anomalyHistoryChart) {
            anomalyHistoryChart.data.labels.push(timeLabel);
            anomalyHistoryChart.data.datasets[0].data.push(data.anomaly_score);

            // Đổi màu đường anomaly nếu phát hiện nguy hiểm
            if (data.anomaly_score >= state.anomalyThreshold) {
                anomalyHistoryChart.data.datasets[0].borderColor = "#ff0055";
            } else {
                anomalyHistoryChart.data.datasets[0].borderColor = "#00ff9d";
            }

            if (anomalyHistoryChart.data.labels.length > 30) {
                anomalyHistoryChart.data.labels.shift();
                anomalyHistoryChart.data.datasets[0].data.shift();
            }
            anomalyHistoryChart.update("none");
        }
    }

    function updateKPIs(data) {
        if (!data) return;

        // Packet rate & byte rate
        if (elements.kpiPacketRate) elements.kpiPacketRate.innerText = Math.round(data.packet_rate);
        if (elements.kpiByteRate) {
            const kbRate = data.byte_rate / 1024;
            elements.kpiByteRate.innerText = kbRate > 1024 ? (kbRate / 1024).toFixed(1) + " MB" : Math.round(kbRate) + " KB";
        }

        // Anomaly Score
        const score = data.anomaly_score || 0.0;
        if (elements.kpiAnomalyScore) elements.kpiAnomalyScore.innerText = score.toFixed(2);
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
            elements.gaugeThreatDesc.innerText = data.is_anomaly ?
                `Phát hiện: ${data.threat_type} (Edge Flag: ${data.edge_prediction})` :
                "Lưu lượng mạng bình thường. Không phát hiện rủi ro.";
        }

        if (elements.kpiTotalThreats) {
            elements.kpiTotalThreats.innerText = state.totalThreats;
        }
    }

    // -------------------------------------------------------------
    // RENDER ALERT TABLE ROW
    // -------------------------------------------------------------
    function renderAlertRow(alert) {
        if (!elements.alertsTableBody || !alert) return;

        const row = document.createElement("tr");
        const timeStr = new Date(alert.timestamp).toLocaleTimeString("vi-VN", { hour12: false });
        
        let sevClass = "threat-normal";
        if (alert.severity === "CRITICAL") sevClass = "threat-critical";
        else if (alert.severity === "HIGH") sevClass = "threat-high";

        row.innerHTML = `
            <td class="mono-text">${timeStr}</td>
            <td class="mono-text" style="color: var(--cyan-neon);">${alert.device_id || "ESP32-Probe"}</td>
            <td><span class="badge-threat ${sevClass}">${alert.threat_type || "Attack"}</span></td>
            <td class="mono-text">${(alert.anomaly_score || 0.95).toFixed(2)}</td>
            <td style="color: var(--text-secondary); font-size: 12px;">${alert.details || "Detected anomaly in traffic window"}</td>
        `;

        // Prepend to top of table
        elements.alertsTableBody.insertBefore(row, elements.alertsTableBody.firstChild);

        // Keep maximum 20 rows visible
        while (elements.alertsTableBody.children.length > 20) {
            elements.alertsTableBody.removeChild(elements.alertsTableBody.lastChild);
        }
    }

    // -------------------------------------------------------------
    // INTERACTIVE ATTACK INJECTOR (REST API)
    // -------------------------------------------------------------
    const attackButtons = document.querySelectorAll(".btn-attack");
    attackButtons.forEach(btn => {
        btn.addEventListener("click", async () => {
            const attackType = btn.getAttribute("data-attack");
            
            // Highlight active button
            attackButtons.forEach(b => b.classList.remove("active-scenario"));
            btn.classList.add("active-scenario");

            try {
                const response = await fetch("/api/simulator/inject", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ attack_type: attackType })
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
            if (elements.thresholdValue) elements.thresholdValue.innerText = val.toFixed(2);
            state.anomalyThreshold = val;
        });

        elements.thresholdSlider.addEventListener("change", async (e) => {
            const val = parseFloat(e.target.value);
            try {
                await fetch("/api/settings/threshold", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ threshold: val })
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
