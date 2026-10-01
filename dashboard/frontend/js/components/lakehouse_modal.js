/**
 * Data Lakehouse & Remote Cloud Explorer Modal Component
 * =====================================================
 * Cung cấp giao diện Web trực quan theo dõi toàn bộ Data Lakehouse (Parquet/SQLite)
 * và kiểm tra trạng thái lưu trữ đối tượng Cloudflare R2 / AWS S3.
 */

export class LakehouseModalComponent {
  constructor() {
    this.modal = document.getElementById("lakehouse-modal");
    this.btnClose = document.getElementById("btn-close-lakehouse-modal");
    this.btnIndicator = document.getElementById("data-lake-indicator");
    this.btnPushR2 = document.getElementById("modal-btn-push-r2");

    this.elRecords = document.getElementById("modal-lake-records");
    this.elSplit = document.getElementById("modal-lake-split");
    this.elStorage = document.getElementById("modal-lake-storage");
    this.elSessionsCount = document.getElementById("modal-lake-sessions-count");
    this.elR2Status = document.getElementById("modal-r2-status");
    this.elR2Bucket = document.getElementById("modal-r2-bucket");
    this.elSessionsBadge = document.getElementById("modal-sessions-badge");
    this.tbodySessions = document.getElementById("modal-lake-sessions-body");

    this.initEventListeners();
  }

  initEventListeners() {
    if (this.btnIndicator) {
      this.btnIndicator.style.cursor = "pointer";
      this.btnIndicator.addEventListener("click", () => this.open());
    }

    if (this.btnClose) {
      this.btnClose.addEventListener("click", () => this.close());
    }

    if (this.modal) {
      this.modal.addEventListener("click", (e) => {
        if (e.target === this.modal) this.close();
      });
    }

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && this.isOpen()) this.close();
    });

    if (this.btnPushR2) {
      this.btnPushR2.addEventListener("click", () => this.triggerPush());
    }
  }

  isOpen() {
    return this.modal && this.modal.style.display === "flex";
  }

  open() {
    if (!this.modal) return;
    this.modal.style.display = "flex";
    this.loadData();
  }

  close() {
    if (!this.modal) return;
    this.modal.style.display = "none";
  }

  async loadData() {
    // 1. Nạp Summary Stats
    try {
      const res = await fetch("/api/data-lake/summary");
      if (res.ok) {
        const s = await res.json();
        if (this.elRecords) this.elRecords.innerText = (s.total_records || 0).toLocaleString();
        if (this.elSplit) this.elSplit.innerText = `Normal: ${(s.normal_records || 0).toLocaleString()} | Attack: ${(s.attack_records || 0).toLocaleString()}`;
        if (this.elStorage) this.elStorage.innerText = `${(s.total_storage_kb || 0).toLocaleString()} KB`;
        if (this.elSessionsCount) this.elSessionsCount.innerText = `${s.total_sessions || 0} sessions Parquet`;
      }
    } catch (e) {
      console.error("Error loading lakehouse summary:", e);
    }

    // 2. Nạp Remote Storage Status (Cloudflare R2)
    try {
      const resR2 = await fetch("/api/remote-storage/status");
      if (resR2.ok) {
        const r2 = await resR2.json();
        if (this.elR2Status) {
          if (r2.available) {
            this.elR2Status.innerHTML = `<span class="status-dot" style="background: var(--emerald-safe);"></span> Online (${r2.provider || "R2"})`;
            this.elR2Status.style.color = "var(--emerald-safe)";
          } else {
            this.elR2Status.innerHTML = `<span class="status-dot" style="background: var(--amber-warning);"></span> ${r2.message || "Chưa cấu hình"}`;
            this.elR2Status.style.color = "var(--amber-warning)";
          }
        }
        if (this.elR2Bucket) {
          this.elR2Bucket.innerText = `Bucket: ${r2.bucket || "edge-lakehouse"} | Endpoint: ${r2.endpoint || "Cloudflare R2"}`;
        }
      }
    } catch (e) {
      if (this.elR2Status) {
        this.elR2Status.innerHTML = `<span class="status-dot" style="background: var(--crimson-danger);"></span> Lỗi kết nối`;
      }
    }

    // 3. Nạp danh sách Sessions
    try {
      const resSessions = await fetch("/api/data-lake/sessions");
      if (resSessions.ok) {
        const sessions = await resSessions.json();
        this.renderSessions(sessions);
      }
    } catch (e) {
      console.error("Error loading lakehouse sessions:", e);
    }
  }

  renderSessions(sessions) {
    if (!this.tbodySessions) return;

    if (!Array.isArray(sessions) || sessions.length === 0) {
      this.tbodySessions.innerHTML = `
        <tr>
          <td colspan="5" style="padding: 20px; text-align: center; color: var(--text-muted);">
            Chưa có phiên thu thập nào trong Data Lakehouse.
          </td>
        </tr>
      `;
      if (this.elSessionsBadge) this.elSessionsBadge.innerText = "0 sessions";
      return;
    }

    if (this.elSessionsBadge) this.elSessionsBadge.innerText = `${sessions.length} sessions gần nhất`;

    this.tbodySessions.innerHTML = sessions.map((s) => {
      const sid = s.session_id || "unknown";
      const start = s.start_time ? new Date(s.start_time * 1000).toLocaleTimeString("vi-VN") : "--";
      const records = (s.records_count || 0).toLocaleString();
      const scenario = s.attack_scenario || "Normal";
      const isAttack = scenario !== "Normal";
      const synced = s.is_synced ? `<span style="color: var(--emerald-safe);">Đã Sync</span>` : `<span style="color: var(--amber-warning);">Chưa Sync</span>`;

      return `
        <tr style="border-bottom: 1px solid rgba(148, 163, 184, 0.08);">
          <td style="padding: 8px 12px; color: #fff;">${sid}</td>
          <td style="padding: 8px 12px; color: var(--text-muted);">${start}</td>
          <td style="padding: 8px 12px; color: var(--cyan-neon);">${records}</td>
          <td style="padding: 8px 12px;">
            <span style="padding: 2px 6px; border-radius: 4px; background: ${isAttack ? 'rgba(255, 0, 85, 0.15)' : 'rgba(0, 255, 157, 0.15)'}; color: ${isAttack ? 'var(--crimson-danger)' : 'var(--emerald-safe)'}; border: 1px solid ${isAttack ? 'rgba(255, 0, 85, 0.3)' : 'rgba(0, 255, 157, 0.3)'};">
              ${scenario}
            </span>
          </td>
          <td style="padding: 8px 12px;">${synced}</td>
        </tr>
      `;
    }).join("");
  }

  async triggerPush() {
    if (!this.btnPushR2) return;
    const oldText = this.btnPushR2.innerText;
    this.btnPushR2.innerText = "⏳ Đang đẩy lên R2...";
    this.btnPushR2.disabled = true;

    try {
      const res = await fetch("/api/remote-storage/push", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        this.btnPushR2.innerText = `✅ Đã Push (${data.uploaded_count || 0} file)`;
        this.btnPushR2.style.borderColor = "var(--emerald-safe)";
        this.btnPushR2.style.color = "var(--emerald-safe)";
        setTimeout(() => {
          this.loadData();
          this.btnPushR2.innerText = oldText;
          this.btnPushR2.disabled = false;
        }, 2000);
      } else {
        alert(`Thông báo: ${data.message || "Chưa thể kết nối tới Cloudflare R2"}`);
        this.btnPushR2.innerText = oldText;
        this.btnPushR2.disabled = false;
      }
    } catch (e) {
      alert(`Lỗi khi gọi API push: ${e}`);
      this.btnPushR2.innerText = oldText;
      this.btnPushR2.disabled = false;
    }
  }
}
