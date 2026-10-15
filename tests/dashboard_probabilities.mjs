import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const source = (await readFile(new URL('../dashboard/frontend/js/components/risk_assessment.js', import.meta.url), 'utf8'))
  .replace('import { eventBus, state } from "../state.js";', 'const eventBus = {}; const state = {};')
  .replace('import { audioService } from "../services/audio_service.js";', 'const audioService = { stopAlarm() {} };');
const { probabilityEntries, RiskAssessmentComponent } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const data = { top_probabilities: { Normal: 95, XSS: 3 }, class_probabilities: { Normal: .95, XSS: .03, DDoS_UDP: .001 } };
assert.deepEqual(probabilityEntries(data, 'DDoS_UDP').at(-1), ['DDoS_UDP', .1]);
assert.equal(probabilityEntries(data, 'Normal').length, 2);
assert.equal(probabilityEntries(data, 'unavailable-class').length, 2);
assert.equal(probabilityEntries({ class_probabilities: {} }, 'DDoS_UDP').length, 0);
assert.equal(probabilityEntries({ ...data, inference_status: 'unavailable' }, 'DDoS_UDP').length, 0);
globalThis.document = { getElementById: () => null };
const risk = Object.create(RiskAssessmentComponent.prototype);
risk.elScoreNumber = { style: {} };
risk.elThreatDesc = {};
risk.elEdgeBadge = { style: {} };
risk.elEdgeModelInfo = {};
risk.elProbBarsList = {};
risk.render({ ...data, inference_status: 'unavailable', anomaly_score: null,
  edge_inference_status: 'unavailable', edge_features_count: 0, edge_prediction: 'Unknown' });
assert.equal(risk.elScoreNumber.innerText, 'N/A');
assert.equal(risk.elEdgeBadge.innerText, 'N/A');
assert.match(risk.elProbBarsList.innerHTML, /N\/A/);
assert.match(risk.elEdgeModelInfo.innerText, /chưa khả dụng/);
risk.render({ ...data, inference_status: 'ok', inference_source: 'esp32', anomaly_score: .7,
  edge_threshold: .8, edge_prediction: 'Normal', edge_inference_status: 'ok', edge_features_count: 10 });
assert.equal(risk.elScoreNumber.innerText, '0.70');
assert.match(risk.elThreatDesc.innerHTML, /bình thường/);
console.log('Selected experiment class remains visible without falsifying probabilities');
