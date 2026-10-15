// Offline component regression with stub DOM and charts; no browser/network.
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const toModule = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const stateUrl = toModule(await readFile(new URL('../dashboard/frontend/js/state.js', import.meta.url), 'utf8'));
const { state, eventBus } = await import(stateUrl);
const elements = new Map();
globalThis.document = { getElementById(id) {
  if (!elements.has(id)) elements.set(id, { innerText: '', style: {} });
  return elements.get(id);
}};
let source = await readFile(new URL('../dashboard/frontend/js/components/kpi_grid.js', import.meta.url), 'utf8');
source = source.replace('"../state.js"', JSON.stringify(stateUrl));
const { KpiGridComponent } = await import(toModule(source));
const grid = new KpiGridComponent();
state.addTelemetry({ inference_status: 'unavailable', anomaly_score: null, severity: 'UNKNOWN' }, 100, 0);
state.addTrafficWindow({ packet_rate: 125, byte_rate: 102400 }, 100);
assert.equal(grid.elPacketRate.innerText, '125');
assert.equal(grid.elByteRate.innerText, '100.0 KB');
assert.equal(grid.elAnomalyScore.innerText, 'N/A');
state.addTelemetry({ inference_status: 'unavailable', anomaly_score: null, severity: 'UNKNOWN' }, 100, 0);
assert.equal(grid.elPacketRate.innerText, '125');
assert.equal(grid.elByteRate.innerText, '100.0 KB');
source = await readFile(new URL('../dashboard/frontend/js/components/charts.js', import.meta.url), 'utf8');
const chartApi = {};
globalThis.__chartApi = chartApi;
source = source.replace('"../state.js"', JSON.stringify(stateUrl))
  .replace('import { ApiService } from "../services/api_service.js";', 'const ApiService = globalThis.__chartApi;');
const { ChartsComponent } = await import(toModule(source));
const charts = Object.create(ChartsComponent.prototype);
const chart = () => ({ data: { labels: [], datasets: [{ data: [] }, { data: [] }] }, update() {} });
charts.trafficRateChart = chart();
charts.anomalyHistoryChart = chart();
charts.protocolDoughnutChart = chart();
charts.updateCharts({ packet_rate: 125, byte_rate: 102400, tcp_ratio: 1, udp_ratio: 0, icmp_ratio: 0 });
charts.updateCharts({ anomaly_score: null });
assert.deepEqual(charts.trafficRateChart.data.datasets[0].data, [125]);
assert.deepEqual(charts.protocolDoughnutChart.data.datasets[0].data, [100, 0, 0]);
assert.deepEqual(charts.anomalyHistoryChart.data.datasets[0].data, [null]);
// Prediction events may carry old/default zero rates. Only measured window
// events may update host throughput after its independent stream is present.
charts.initEventListeners();
state.addTrafficWindow({ packet_rate: 2000, byte_rate: 2048000, tcp_ratio: 0, udp_ratio: 1, icmp_ratio: 0 });
for (let i = 0; i < 30; i++) {
  state.addTelemetry({ record_kind: 'packet', packet_rate: 0, byte_rate: 0,
    tcp_ratio: 0, anomaly_score: 0.2, inference_status: 'ok' });
}
assert.deepEqual(charts.trafficRateChart.data.datasets[0].data, [125, 2000]);
assert.deepEqual(charts.protocolDoughnutChart.data.datasets[0].data, [0, 100, 0]);
state.addTrafficWindow({ packet_rate: 0, byte_rate: 0, tcp_ratio: 0, udp_ratio: 0, icmp_ratio: 0 });
assert.deepEqual(charts.trafficRateChart.data.datasets[0].data, [125, 2000, 0]);
assert.equal(charts.anomalyHistoryChart.data.labels.length, 25);
const windowPoint = { record_kind: 'window', timestamp: 1791738838167, capture_id: 'capture-1', device_id: 'host', packet_rate: 1855.29, byte_rate: 85876.62, tcp_ratio: 1, udp_ratio: 0, icmp_ratio: 0 };
state.addTrafficWindow(windowPoint);
const length = charts.trafficRateChart.data.labels.length;
state.addTrafficWindow(windowPoint); // Poll and WebSocket must not duplicate a window.
assert.equal(charts.trafficRateChart.data.labels.length, length);
assert.equal(charts.trafficRateChart.data.datasets[0].data.at(-1), 1855.29);
assert.deepEqual(charts.protocolDoughnutChart.data.datasets[0].data, [100, 0, 0]);
chartApi.getStatus = async () => ({ capture_health: { ...windowPoint, timestamp: windowPoint.timestamp + 1000, packet_rate: 2176 } });
await charts.refreshTrafficWindow();
assert.equal(charts.trafficRateChart.data.datasets[0].data.at(-1), 2176);
console.log('Dashboard window/packet component regressions passed');
