/**
 * WiFi Spectrum & Discovered Networks Component
 * ============================================
 * Hiển thị danh sách các mạng WiFi (SSID) do ESP-32 Promiscuous Sniffer
 * (hoặc Host Network Probe) bắt được qua sóng.
 */

import { state, eventBus } from "../state.js";

export class WifiInspectorComponent {
  constructor() {
    this.container = document.getElementById("wifi-networks-grid");
    this.badge = document.getElementById("wifi-networks-counter-badge");
    this.btnRefresh = document.getElementById("btn-refresh-wifi");

    this.initEventListeners();
    this.fetchInitialNetworks();
  }

  initEventListeners() {
    eventBus.on("wifiNetworksUpdated", (networks) => this.render(networks));
    eventBus.on("stateChanged", () => {
      if (state.detectedWifiNetworks && state.detectedWifiNetworks.length > 0) {
        this.render(state.detectedWifiNetworks);
      }
    });

    if (this.btnRefresh) {
      this.btnRefresh.addEventListener("click", () => this.fetchInitialNetworks());
    }
  }

  async fetchInitialNetworks() {
    try {
      const res = await fetch("/api/wifi/networks");
      if (res.ok) {
        const data = await res.json();
        if (data.networks && Array.isArray(data.networks)) {
          state.updateWifiNetworks(data.networks);
        }
      }
    } catch (e) {
      // Bỏ qua lỗi kết nối ban đầu
    }
  }

  getSignalQuality(rssi) {
    if (rssi >= -60) return { class: "wifi-signal-excellent", text: "Xuất Sắc", color: "var(--emerald-safe)" };
    if (rssi >= -72) return { class: "wifi-signal-good", text: "Tốt", color: "var(--cyan-neon)" };
    if (rssi >= -82) return { class: "wifi-signal-fair", text: "Trung Bình", color: "var(--amber-warning)" };
    return { class: "wifi-signal-weak", text: "Yếu", color: "var(--crimson-danger)" };
  }

  render(networks) {
    if (!this.container) return;

    const list = Array.isArray(networks) ? networks : state.detectedWifiNetworks || [];

    if (this.badge) {
      if (list.length > 0) {
        this.badge.innerText = `📡 ${list.length} Mạng Bắt Được`;
        this.badge.style.color = "var(--cyan-neon)";
        this.badge.style.borderColor = "var(--cyan-neon)";
      } else {
        this.badge.innerText = "📡 Đang dò sóng...";
      }
    }

    if (list.length === 0) {
      this.container.innerHTML = `
        <div style="grid-column: 1 / -1; padding: 24px; text-align: center; color: var(--text-muted); font-size: 13px; font-family: var(--font-mono); background: rgba(15, 23, 42, 0.4); border-radius: 8px; border: 1px dashed rgba(148, 163, 184, 0.2);">
          Đang lắng nghe khung phát sóng WiFi (Beacon frames) từ ESP32 over-the-air...
        </div>
      `;
      return;
    }

    // Sắp xếp theo cường độ tín hiệu giảm dần (mạng mạnh nhất lên đầu)
    const sorted = [...list].sort((a, b) => (b.rssi || -100) - (a.rssi || -100));

    this.container.innerHTML = sorted.map((net) => {
      const ssid = net.ssid || "Unknown SSID";
      const rssi = net.rssi !== undefined ? net.rssi : -75;
      const channel = net.channel || 1;
      const qual = this.getSignalQuality(rssi);

      return `
        <div class="wifi-item-card">
          <div style="display: flex; align-items: center; gap: 10px; overflow: hidden;">
            <div class="wifi-signal-meter ${qual.class}" title="Tín hiệu: ${qual.text} (${rssi} dBm)">
              <div class="wifi-signal-bar"></div>
              <div class="wifi-signal-bar"></div>
              <div class="wifi-signal-bar"></div>
              <div class="wifi-signal-bar"></div>
            </div>
            <div style="overflow: hidden;">
              <div style="font-weight: 600; font-size: 13px; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${ssid}">
                ${ssid}
              </div>
              <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
                <span style="color: ${qual.color};">${rssi} dBm</span> &bull; ${qual.text}
              </div>
            </div>
          </div>
          <div style="display: flex; flex-direction: column; align-items: flex-end; flex-shrink: 0;">
            <span style="font-size: 10px; padding: 2px 7px; border-radius: 4px; background: rgba(168, 85, 247, 0.15); color: var(--purple-accent); border: 1px solid rgba(168, 85, 247, 0.3); font-family: var(--font-mono);">
              CH ${channel}
            </span>
          </div>
        </div>
      `;
    }).join("");
  }
}
