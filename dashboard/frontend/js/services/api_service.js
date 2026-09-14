/**
 * REST API Client Service
 * =======================
 * Giao tiếp với FastAPI Backend để điều khiển bắn gói tin mạng thật, cập nhật ngưỡng.
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

  static async getAttackStatus() {
    try {
      const res = await fetch("/api/attack/status");
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to fetch attack status:", err);
      return null;
    }
  }

  static async triggerAttack(attackType, targetIp = null) {
    try {
      const res = await fetch("/api/attack/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_type: attackType,
          target_ip: targetIp
        })
      });
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to trigger attack:", err);
      return null;
    }
  }

  static async stopAttack() {
    try {
      const res = await fetch("/api/attack/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to stop attack:", err);
      return null;
    }
  }

  static async toggleAutoCycle(enabled = true) {
    try {
      const res = await fetch("/api/attack/auto-cycle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled })
      });
      return await res.json();
    } catch (err) {
      console.error("[ApiService] Failed to toggle auto cycle:", err);
      return null;
    }
  }

  static async setSimulatorScenario(attackType) {
    return await this.triggerAttack(attackType);
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
