/**
 * Charts Component (Chart.js)
 * ===========================
 * Quản lý 3 biểu đồ trực quan hóa thời gian thực:
 * 1. Lưu lượng gói tin & Băng thông (Throughput Line Chart).
 * 2. Phân bố giao thức mạng (Protocol Doughnut Chart).
 * 3. Biến thiên chỉ số Anomaly Score (Line Chart) & Thanh trượt ngưỡng (Threshold Slider).
 */

import { state, eventBus } from "../state.js";
import { ApiService } from "../services/api_service.js";

export class ChartsComponent {
  constructor() {
    this.trafficRateChart = null;
    this.protocolDoughnutChart = null;
    this.anomalyHistoryChart = null;

    this.slider = document.getElementById("threshold-slider");
    this.sliderValue = document.getElementById("threshold-value");

    this.initCharts();
    this.initEventListeners();
    this.polling = false;
    this.refreshTrafficWindow();
    setInterval(() => this.refreshTrafficWindow(), 2000);
  }

  async refreshTrafficWindow() {
    if (this.polling || !ApiService.getStatus) return;
    this.polling = true;
    try {
      const status = await ApiService.getStatus();
      if (status?.capture_health) state.addTrafficWindow(status.capture_health);
    } finally {
      this.polling = false;
    }
  }

  initCharts() {
    if (typeof Chart === "undefined") {
      console.warn("[ChartsComponent] Chart.js is not loaded yet.");
      return;
    }

    Chart.defaults.color = "#a8b8b3";
    Chart.defaults.font.family = "'IBM Plex Mono', monospace";

    // 1. Throughput Line Chart
    const trafficCanvas = document.getElementById("trafficRateChart");
    if (trafficCanvas) {
      const trafficCtx = trafficCanvas.getContext("2d");
      const gradientPackets = trafficCtx.createLinearGradient(0, 0, 0, 300);
      gradientPackets.addColorStop(0, "rgba(143, 211, 185, 0.34)");
      gradientPackets.addColorStop(1, "rgba(143, 211, 185, 0.0)");

      this.trafficRateChart = new Chart(trafficCtx, {
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
              yAxisID: "yPackets"
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
              yAxisID: "yBytes"
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          scales: {
            x: {
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              ticks: { maxTicksLimit: 8, font: { size: 10 } }
            },
            yPackets: {
              type: "linear",
              position: "left",
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              title: { display: true, text: "Pkts/s", color: "#8fd3b9", font: { size: 11 } }
            },
            yBytes: {
              type: "linear",
              position: "right",
              grid: { drawOnChartArea: false },
              title: { display: true, text: "KB/s", color: "#b9a7db", font: { size: 11 } }
            }
          },
          plugins: {
            legend: { labels: { boxWidth: 12, font: { size: 11 } } }
          }
        }
      });
    }

    // 2. Protocol Doughnut Chart
    const protoCanvas = document.getElementById("protocolChart");
    if (protoCanvas) {
      const protoCtx = protoCanvas.getContext("2d");
      this.protocolDoughnutChart = new Chart(protoCtx, {
        type: "doughnut",
        data: {
          labels: ["TCP", "UDP", "ICMP"],
          datasets: [
            {
              data: [0, 0, 0],
              backgroundColor: ["#8fd3b9", "#b9a7db", "#e5989b"],
              borderColor: "#0f172a",
              borderWidth: 2,
              hoverOffset: 4
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "bottom", labels: { boxWidth: 12, padding: 15 } }
          },
          cutout: "68%"
        }
      });
    }

    // 3. Anomaly Score Evolution Chart
    const anomalyCanvas = document.getElementById("anomalyScoreChart");
    if (anomalyCanvas) {
      const anomalyCtx = anomalyCanvas.getContext("2d");
      this.anomalyHistoryChart = new Chart(anomalyCtx, {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "Anomaly Score",
              data: [],
              borderColor: "#e5989b",
              backgroundColor: "rgba(229, 152, 155, 0.12)",
              borderWidth: 2,
              pointRadius: 2,
              fill: true,
              tension: 0.2
            },
            {
              label: "Ngưỡng Cảnh Báo",
              data: [],
              borderColor: "#ffb703",
              borderWidth: 1.5,
              borderDash: [5, 5],
              pointRadius: 0,
              fill: false
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          scales: {
            x: {
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              ticks: { maxTicksLimit: 6, font: { size: 10 } }
            },
            y: {
              min: 0.0,
              max: 1.0,
              grid: { color: "rgba(255, 255, 255, 0.05)" },
              ticks: { stepSize: 0.2 }
            }
          },
          plugins: {
            legend: { labels: { boxWidth: 12 } }
          }
        }
      });
    }
  }

  initEventListeners() {
    // Packet predictions never supply rates for the host's measured window.
    eventBus.on("telemetryReceived", (data) => this.updateCharts(data,
      !state.latestTrafficWindow && data.record_kind !== "packet"));
    eventBus.on("trafficWindowReceived", (data) => this.updateCharts(data, true));
    eventBus.on("initialStateLoaded", () => this.syncThreshold());

    if (this.slider && this.sliderValue) {
      this.slider.addEventListener("input", (e) => {
        const val = parseFloat(e.target.value).toFixed(2);
        this.sliderValue.innerText = val;
      });

      this.slider.addEventListener("change", async (e) => {
        const val = parseFloat(e.target.value);
        state.anomalyThreshold = val;
        await ApiService.setAnomalyThreshold(val);
      });
    }
  }

  syncThreshold() {
    if (this.slider && this.sliderValue) {
      this.slider.value = state.anomalyThreshold;
      this.sliderValue.innerText = Number(state.anomalyThreshold).toFixed(2);
    }
  }

  updateCharts(data, updateTraffic = data.record_kind !== "packet") {
    const timeLabel = new Date(data.timestamp || Date.now()).toLocaleTimeString("vi-VN", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });

    // Cập nhật Throughput Chart
    if (updateTraffic && this.trafficRateChart && Number.isFinite(data.packet_rate) && Number.isFinite(data.byte_rate)) {
      const d = this.trafficRateChart.data;
      d.labels.push(timeLabel);
      d.datasets[0].data.push(data.packet_rate || 0);
      d.datasets[1].data.push(Number(((data.byte_rate || 0) / 1024).toFixed(1)));

      if (d.labels.length > 25) {
        d.labels.shift();
        d.datasets[0].data.shift();
        d.datasets[1].data.shift();
      }
      this.trafficRateChart.update();
    }

    // Cập nhật Protocol Chart (Hỗ trợ cả window ratio và luồng gói tin mã hóa riêng lẻ)
    if (this.protocolDoughnutChart) {
      if (Number.isFinite(data.tcp_ratio)) {
        const udp = data.udp_ratio ?? 0;
        const icmp = data.icmp_ratio ?? 0;
        const tcp = data.tcp_ratio;

        this.protocolDoughnutChart.data.datasets[0].data = [
          Math.round(tcp * 100),
          Math.round(udp * 100),
          Math.round(icmp * 100)
        ];
        this.protocolDoughnutChart.update();
      } else if (data.protocol) {
        if (!this.packetProtoCounts) this.packetProtoCounts = { TCP: 0, UDP: 0, ICMP: 0 };
        const p = String(data.protocol).toUpperCase();
        if (p.includes("TCP")) this.packetProtoCounts.TCP++;
        else if (p.includes("UDP")) this.packetProtoCounts.UDP++;
        else if (p.includes("ICMP")) this.packetProtoCounts.ICMP++;
        const total = this.packetProtoCounts.TCP + this.packetProtoCounts.UDP + this.packetProtoCounts.ICMP;
        if (total > 0) {
          this.protocolDoughnutChart.data.datasets[0].data = [
            Math.round((this.packetProtoCounts.TCP / total) * 100),
            Math.round((this.packetProtoCounts.UDP / total) * 100),
            Math.round((this.packetProtoCounts.ICMP / total) * 100)
          ];
          this.protocolDoughnutChart.update();
        }
      }
    }

    // Cập nhật Anomaly Evolution Chart
    if (this.anomalyHistoryChart && Object.hasOwn(data, "anomaly_score")) {
      const d = this.anomalyHistoryChart.data;
      d.labels.push(timeLabel);
      d.datasets[0].data.push(Number.isFinite(data.anomaly_score) ? Number(data.anomaly_score.toFixed(3)) : null);
      d.datasets[1].data.push(data.inference_source === "esp32" && Number.isFinite(data.edge_threshold)
        ? data.edge_threshold : state.anomalyThreshold);

      if (d.labels.length > 25) {
        d.labels.shift();
        d.datasets[0].data.shift();
        d.datasets[1].data.shift();
      }
      this.anomalyHistoryChart.update();
    }
  }
}
