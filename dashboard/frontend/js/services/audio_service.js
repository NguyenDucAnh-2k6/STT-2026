/**
 * Web Audio API Synthesizer Service
 * =================================
 * Phát sinh âm thanh cảnh báo trực tiếp qua trình duyệt (Synthesizer).
 */

import { state } from "../state.js";

export class AudioService {
  constructor() {
    this.audioCtx = null;
    this.lastAlarmTime = 0;
  }

  initContext() {
    if (!this.audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) {
        this.audioCtx = new AudioContextClass();
      }
    }
    if (this.audioCtx && this.audioCtx.state === "suspended") {
      this.audioCtx.resume();
    }
  }

  playThreatAlarm(severity = "HIGH") {
    if (!state.audioEnabled) return;
    try {
      this.initContext();
      if (!this.audioCtx) return;

      const now = Date.now();
      if (now - this.lastAlarmTime < 1200) return; // Tránh phát quá dồn dập
      this.lastAlarmTime = now;

      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.connect(gain);
      gain.connect(this.audioCtx.destination);

      if (severity === "CRITICAL") {
        // Còi báo động khẩn cấp (Police Siren)
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, this.audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1350, this.audioCtx.currentTime + 0.15);
        osc.frequency.exponentialRampToValueAtTime(880, this.audioCtx.currentTime + 0.35);
        gain.gain.setValueAtTime(0.15, this.audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.audioCtx.currentTime + 0.42);
        osc.start();
        osc.stop(this.audioCtx.currentTime + 0.45);
      } else {
        // Tiếng beep cảnh báo nhanh
        osc.type = "sine";
        osc.frequency.setValueAtTime(750, this.audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1050, this.audioCtx.currentTime + 0.12);
        gain.gain.setValueAtTime(0.12, this.audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.audioCtx.currentTime + 0.3);
        osc.start();
        osc.stop(this.audioCtx.currentTime + 0.32);
      }
    } catch (e) {
      console.warn("[AudioService] Failed to play sound:", e);
    }
  }
}

export const audioService = new AudioService();
