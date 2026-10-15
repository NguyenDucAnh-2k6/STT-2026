// Offline UI wiring/acknowledgment checks; no browser or network traffic.
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const html = await readFile(new URL('../dashboard/frontend/index.html', import.meta.url), 'utf8');
const group = html.match(/<div class="control-buttons-group">([\s\S]*?)<\/div>/)[1];
const labels = [...group.matchAll(/data-attack="([^"]+)"/g)].map(match => match[1]);
assert.equal(labels.length, 15);
assert.equal(new Set(labels).size, 15);
for (const label of ['DDoS_ICMP', 'Password', 'Fingerprinting', 'MITM', 'Backdoor', 'Ransomware']) {
  assert.ok(labels.includes(label));
}
assert.ok(labels.includes('DDoS_HTTP') && labels.includes('XSS'));
let component;
let sequence = 0;
const calls = [];
const state = { attackStatus: { status: 'IDLE', scenario: 'Normal', auto_cycle: false },
  updateExperimentStatus(status) { this.experimentStatus = status; } };
const api = {
  async triggerAttack(label) { return respond(label); },
  async stopAttack() { return respond('Normal'); },
  async toggleAutoCycle(enabled) { return respond(`cycle:${enabled}`); }
};
function respond(label) {
  calls.push(label);
  const command_id = String(++sequence);
  // Ack can arrive before REST response: renderStatus must still accept it.
  state.attackStatus = { status: label === 'Normal' ? 'IDLE' : 'ATTACKING',
    scenario: label, command_id, expires_at_ms: Date.now() + 60000 };
  return { status: 'accepted', command_id };
}
const timers = new Map();
globalThis.setInterval = () => 0;
globalThis.setTimeout = fn => { timers.set(sequence, fn); return sequence; };
globalThis.clearTimeout = id => timers.delete(id);
globalThis.alert = () => {};
globalThis.__controlTest = { api, state, eventBus: { on() {} } };
function element(label) {
  return { style: {}, textContent: '', listeners: {}, classes: new Set(),
    addEventListener(type, callback) { this.listeners[type] = callback; },
    getAttribute() { return label; },
    classList: { add() {}, remove() {} } };
}
const buttons = labels.map(element);
const elements = new Map(['btn-auto-cycle', 'btn-stop-experiment', 'attack-status-display', 'attack-target-display'].map(id => [id, element()]));
globalThis.document = { querySelectorAll: () => buttons, getElementById: id => elements.get(id) };
let source = await readFile(new URL('../dashboard/frontend/js/components/control_bar.js', import.meta.url), 'utf8');
source = source.replace('import { ApiService } from "../services/api_service.js";',
  'const ApiService = globalThis.__controlTest.api;').replace('import { eventBus, state } from "../state.js";',
  'const { eventBus, state } = globalThis.__controlTest;');
const { ControlBarComponent } = await import(moduleUrl(source));
component = new ControlBarComponent();
for (let i = 0; i < buttons.length; i++) {
  await buttons[i].listeners.click();
  assert.equal(calls.at(-1), labels[i]);
  assert.equal(component.pendingCommand, null);
  assert.equal(buttons[i].style.opacity, '1.0');
}
api.triggerAttack = async () => ({ status: 'accepted', command_id: 'no-ack' });
await buttons[1].listeners.click();
assert.match(component.statusBadge.textContent, /Đang chờ/);
[...timers.values()][0]();
assert.match(component.statusBadge.textContent, /chưa xác nhận/);
component.renderStatus(state.attackStatus);
assert.match(component.statusBadge.textContent, /chưa xác nhận/);
api.triggerAttack = async () => { throw Error('offline'); };
await buttons[1].listeners.click();
assert.equal(component.sending, false);
assert.equal(buttons[1].style.opacity, '1.0');
assert.match(component.statusBadge.textContent, /offline/);
component.commandError = false;
component.renderStatus({ status: 'ATTACKING', scenario: 'Uploading', expires_at_ms: Date.now() - 1 });
assert.match(component.statusBadge.textContent, /đã cũ/);
state.experimentStatus = { experiment_id: 'session-test', command_id: 'collect', scenario: 'Normal', phase: 'RUNNING' };
component.renderCurrentStatus();
assert.ok(buttons.every(button => button.disabled));
assert.equal(elements.get('btn-stop-experiment').disabled, false);
assert.match(component.statusBadge.textContent, /Đang bắn: Normal/);
assert.equal(component.statusBadge.style.borderColor, 'var(--amber-warning)');
api.stopAttack = async () => ({ status: 'accepted', command_id: 'collect' });
await elements.get('btn-stop-experiment').listeners.click();
assert.equal(component.pendingCommand, null);
state.experimentStatus = { ...state.experimentStatus, phase: 'COMPLETED', saved_rows: 30, labeled_rows: 25, verified_rows: 25, unknown_rows: 5 };
component.renderCurrentStatus();
assert.ok(buttons.every(button => !button.disabled));
assert.match(component.statusBadge.textContent, /Nhãn tự động 25/);
// REST acceptance must render pending collection even if no WebSocket event arrives.
api.triggerAttack = async () => ({ status: 'accepted', experiment_id: 'new-session', command_id: 'new-command', scenario: 'DDoS_TCP', phase: 'STARTING' });
await buttons[3].listeners.click();
assert.match(component.statusBadge.textContent, /Đang chuẩn bị: DDoS_TCP/);
assert.equal(component.pendingCommand, null);
assert.equal(timers.size, 0);
// Polling reconciles the workload's authoritative state without WebSocket delivery.
api.getExperimentStatus = async () => ({ ...state.experimentStatus, phase: 'RUNNING' });
await component.refreshExperimentStatus();
component.renderCurrentStatus();
assert.match(component.statusBadge.textContent, /Đang bắn: DDoS_TCP/);
assert.equal(component.statusBadge.style.background, 'var(--amber-glow)');
state.attackStatus = { status: 'IDLE', scenario: 'Normal' };
component.renderCurrentStatus();
assert.match(component.statusBadge.textContent, /Đang bắn: DDoS_TCP/);
state.experimentStatus.phase = 'IMPORTING';
component.renderCurrentStatus();
assert.match(component.statusBadge.textContent, /Đang lưu: DDoS_TCP/);
state.experimentStatus.phase = 'ERROR';
state.experimentStatus.error = 'capture failed';
component.renderCurrentStatus();
assert.match(component.statusBadge.textContent, /capture failed/);
assert.equal(component.statusBadge.style.borderColor, 'var(--crimson-danger)');
const twinSource = await readFile(new URL('../dashboard/frontend/js/components/digital_twin_lab.js', import.meta.url), 'utf8');
assert.ok(!twinSource.includes('getElementById("attack-status-display")'), 'Twin toast must not own experiment badge');
console.log('Attack button mapping, ACK timeout, failure cleanup, and stale status checks passed');
