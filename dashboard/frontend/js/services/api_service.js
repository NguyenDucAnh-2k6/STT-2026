/**
 * REST API Client Service
 * =======================
 * Giao tiếp với FastAPI Backend để điều khiển bắn gói tin mạng thật, cập nhật ngưỡng.
 */

export class ApiService {
  static async getExperimentStatus() {
    const response = await fetch("/api/experiments/status", { cache: "no-store", signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`Không đọc được trạng thái Twin (HTTP ${response.status})`);
    return await response.json();
  }
  static async getStatus() {
    try {
      const res = await fetch("/api/status", { cache: "no-store", signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
      const res = await fetch("/api/experiments/start", {
        signal: AbortSignal.timeout(8000),
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario: attackType,
          duration_sec: Number(document.getElementById("experiment-duration")?.value || 15)
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
      const res = await fetch("/api/experiments/stop", {
        signal: AbortSignal.timeout(8000),
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
        signal: AbortSignal.timeout(8000),
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
