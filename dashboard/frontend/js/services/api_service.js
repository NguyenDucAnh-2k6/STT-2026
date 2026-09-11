/**
 * REST API Client Service
 * =======================
 * Giao tiếp với FastAPI Backend để điều khiển kịch bản, cập nhật ngưỡng.
 */

export class ApiService {
  static async getStatus() {
    try {
      const res = await fetch("/api/status");
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to fetch status:", err);
      return null;
    }
  }

  static async setSimulatorScenario(attackType) {
    try {
      const res = await fetch("/api/simulator/scenario", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: attackType })
      });
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to inject scenario:", err);
      return null;
    }
  }

  static async setAnomalyThreshold(threshold) {
    try {
      const res = await fetch("/api/config/threshold", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threshold: parseFloat(threshold) })
      });
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to update threshold:", err);
      return null;
    }
  }

  static async getAlerts(limit = 20) {
    try {
      const res = await fetch(`/api/alerts?limit=${limit}`);
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to fetch alerts:", err);
      return [];
    }
  }
}
