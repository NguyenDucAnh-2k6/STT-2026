# MQTT data contract

Reviewed 2026-10-11. MQTT 3.1.1, UTF-8 JSON. Example values are illustrative.

## Actual topics and delivery

| Topic | Producer -> consumer | QoS / retain |
|---|---|---|
| `edge/telemetry/traffic` | Host and ESP32-decoded packets -> inference, collector; ESP32/USB windows | Packets: 1 / false; firmware windows: 0 / false |
| `edge/telemetry/radio` | ESP32 raw radio samples -> host TShark decoder | Firmware: 0 / false; USB: 1 / false |
| `edge/telemetry/window` | Host window statistics -> dashboard, Digital Twin | 0 / false |
| `edge/telemetry/prediction` | Inference -> dashboard | 0 / false |
| `edge/alerts/high_priority` | Valid inference -> dashboard | 0 / false |
| `edge/nodes/status` | Probe -> dashboard | ESP32: 0 / true |
| `edge/attack/control` | Dashboard trigger/stop/auto-cycle -> simulator | 1 / false; subscriber QoS 1, command_id acknowledgment |
| `edge/attack/status` | Simulator -> listeners, collector | 1 / true; context, not ground truth |
| `edge/config/threshold` | Dashboard -> inference/ESP32 | Finite value in [0,1] |

QoS 0 is not guaranteed delivery. Old QoS 1 alert/status claims and `edge/simulator/control` did not match current publishers. Action commands must not be retained. Anonymous plaintext broker config is for a lab.

## Host window

The default host TShark path now sends individual packets on `edge/telemetry/traffic`.
The window example below uses `edge/telemetry/window`. Explicit `--no-tshark` retains
the legacy aggregate path and cannot supply packet training data.

```json
{
  "schema_version": 2,
  "device_id": "Host-PC-Live-Probe",
  "probe_type": "host",
  "record_kind": "window",
  "feature_semantics": "window-v1",
  "capture_backend": "tshark",
  "timestamp": 1800000000000,
  "timestamp_kind": "epoch_ms",
  "window_ms": 1000,
  "packet_rate": 120.0,
  "byte_rate": 60000.0,
  "avg_packet_size": 500.0,
  "syn_ratio": 0.1,
  "label_verified": false,
  "label_source": "unverified"
}
```

Raw socket/psutil fallback windows do not form canonical packets. Psutil only supports aggregate I/O. Host uses connected OS interfaces; Wi-Fi credentials do not make it join a network.

## Host canonical packet

`firmware/host_probe/packet_capture.py` extracts all 56 names in canonical order
using native TShark `-T fields`, first occurrence, quoted tab separation and escaped
control characters. Numeric hexadecimal values are parsed as integers, booleans as
0/1, presence fields (`FT_NONE`) as 1 when present. TCP byte strings stay categorical;
`icmp.unused` bytes become an integer. `mqtt.msg_decoded_as` is categorical because
TShark defines it as text; retraining uses the updated categorical mapping.

Each JSON object contains the 56 **raw**, unscaled feature fields plus:

```json
{
  "schema_version": 2,
  "record_kind": "packet",
  "feature_semantics": "edgeiiot-packet-v1",
  "device_id": "Host-PC-Live-Probe",
  "capture_id": "unique-per-capture",
  "packet_id": "unique-per-capture:123",
  "sequence": 123,
  "timestamp": 1800000000000,
  "packet_time_epoch": 1800000000.000123,
  "timestamp_kind": "epoch_ms",
  "capture_backend": "tshark",
  "dissection_mode": "live-one-pass",
  "extractor_version": "tshark-packet-v1",
  "field_occurrence": "first",
  "missing_features": [],
  "absent_fields": ["mqtt.topic"],
  "label_verified": false,
  "label_source": "unverified",
  "ground_truth_scenario": "Unknown"
}
```

Absent dissector fields use the benchmark-style zero sentinel and are listed in
`absent_fields`. This means **not present in this dissection**, not recovered plaintext
or proof of benign traffic. Unsupported fields stop startup. Malformed numeric fields
become null and appear in `missing_features`; truncated frames mark all features missing.
Encrypted application content stays absent. No aggregate value substitutes for a packet field.

Live capture excludes TCP traffic to/from the resolved telemetry broker addresses on
the configured port to prevent telemetry feedback. MQTT traffic on other broker
addresses is still captured. If survey MQTT shares the same broker endpoint, use a
separate telemetry port or offline PCAP replay. `HOST_PCAP_FILE` selects `-2 -r` two-pass extraction
with no transport-port exclusion. Live one-pass results cannot reproduce fields requiring
future packets; do not assume live and offline reassembly/analysis are identical.
`dns.retransmit_request_in` specifically points to an earlier original request, not a future
packet. TShark retains stream state during the capture. Exact equality to the author's CSV is not established without
the original PCAP, dissector version/preferences and multi-occurrence policy.

Host publishing has a bounded 128-record queue, 1 MB JSON limit, counters for queue drops,
publish failures and rejected packets. Up to 16 publishes wait for ACK concurrently;
shutdown drains with a five-second deadline. QoS 1 acknowledgment is a broker acknowledgment,
not confirmation of Parquet persistence; disconnects/overflow can still lose records.
The collector deduplicates packet identities, including packets sharing a millisecond.
Immutable batches are stored in `data_lake/raw/date=YYYY-MM-DD/`, with `packet_batches`
catalog metadata. Manually reviewed or automatically flow-attributed labels pass the label gate; valid packet features/identity are also required.
New unlabeled captures are preserved but are not automatically appended to training.

## UI scenario labels in Parquet (local lab phase 1)

The collector subscribes to `edge/attack/status` at QoS 1, alongside traffic. Status
includes `experiment_id`, epoch-ms `timestamp`, `expires_at_ms` (at most 60 seconds),
canonical `scenario`, `status`, `target_ip`, `implementation_status`, and `error`.
Unknown/unimplemented names are rejected; the generator never falls back to UDP.
Publish acceptance from `/api/attack/trigger` is returned as `accepted`, not execution success.

Epoch-timestamped packets received after a corresponding status event are annotated
with `requested_attack_label`, `experiment_id`, `scenario_status`, `scenario_target_ip`,
`scenario_target_match`, `scenario_implementation_status`,
`scenario_label_source=ui_scenario`, `scenario_label_scope=time_interval_context`, and
`scenario_label_verified=false`. These fields are persisted independently of prediction
and `ground_truth_scenario`. They are metadata, never model features.

The latest status at the packet capture time is used, with a bounded 128-event history.
Expired status, stopped experiments, missing history and ESP32 uptime timestamps do
not become verified labels. Status/traffic are independent MQTT publishers: a packet
arriving before its status can be annotated while still buffered. A status arriving
after persistence cannot annotate that batch; persisted batches are not rewritten.
Background packets in an experiment interval may carry the requested scenario context,
but are not ground truth. Endpoint match alone also does not verify an attack flow.
Training accepts canonical labels sourced from controlled_flow/manual_review without a verified flag; global UI context alone remains ineligible.

`LAB_TARGET_IP`, `LAB_ALLOWED_TARGETS`, `LAB_HTTP_PORT` configure an explicit lab.
No router/public target discovery or secondary broadcast traffic is used. The local
HTTP endpoint is a non-executing test service; a completed HTTP request is not proof
of SQLi/XSS exploitation or denial of service.

## ESP32 radio window

Updated firmware also emits sampled raw frames on `edge/telemetry/radio` and
`ESP32_RADIO:` USB lines. Host TShark dissection publishes packet rows with the
canonical columns and `capture_backend=esp32_tshark` on `edge/telemetry/traffic`.
Protected/fragmented/non-network frames retain null unavailable features and never
become zero-filled model inputs. Radio packet rows are excluded from supervised
training. See [ESP32 collection](ESP32_PACKET_COLLECTION.md) for limits and startup.
Windows add `radio_capture_version=1`, queue/skip counters and cumulative
`captured_packets`; they also publish on `edge/telemetry/window` for dashboard rates.
Updated Edge AI firmware carries local results in radio messages:
`edge_input_profile=esp32-l234-packet-v1`, `edge_model_version`, `edge_raw_features`,
`edge_inference_status`, `edge_error`, `edge_threshold`, `edge_anomaly_score`,
`edge_flag`, `edge_prediction`, `edge_confidence`, `edge_class_probabilities` and
`edge_latency_ms`. Ten canonical numeric fields are extracted on chip; encrypted,
unsupported, truncated and fragmented inputs remain unavailable. Python validates
and forwards these decisions, without loading host models in ESP32 mode.
Native rows use schema 3, `capture_backend=esp32_native`, profile feature semantics
and `:native:` packet IDs; unmeasured canonical fields remain null. Optional TShark
views use distinct `:radio:` IDs. Predictions carry `inference_source=esp32` and the
applied device threshold; UI does not substitute the host threshold.
See [ESP32 Edge AI](ESP32_EDGE_AI.md) for measured performance and export parity.

```json
{
  "schema_version": 2,
  "device_id": "ESP32-EdgeProbe-01",
  "probe_type": "esp32",
  "record_kind": "window",
  "feature_semantics": "window-v1",
  "capture_backend": "wifi_promiscuous",
  "boot_id": 123456,
  "sequence": 20,
  "timestamp": 42000,
  "timestamp_kind": "uptime_ms",
  "window_ms": 2000,
  "channel": 6,
  "sniffer_mode": "ap-locked",
  "packet_rate": 50.0,
  "byte_rate": 25000.0,
  "avg_packet_size": 500.0,
  "protocol_features_available": false,
  "observed_tcp_count": 2,
  "observed_udp_count": 1,
  "observed_icmp_count": 0,
  "observed_unique_port_buckets": 2,
  "unique_dst_ports_kind": "hashed_estimate",
  "label_verified": false,
  "label_source": "unverified",
  "edge_inference_status": "unavailable",
  "edge_flag": null,
  "edge_prediction": "Unknown",
  "edge_features_count": 0,
  "scanned_networks": []
}
```

Timestamp is uptime, not UTC. Lake preserves `source_timestamp`, adds `received_at_ms`, and uses receipt epoch time. Observed counts are plaintext frames, not total TCP/UDP under WPA; port buckets can collide. The radio can observe other BSSIDs on the same channel. Window-v1 does not guarantee host/radio measurement parity.

All-networks mode disconnects AP and hops channels: JSON uses `sniffer_mode=all-networks` and travels as `ESP32_TELEMETRY:` USB Serial -> Python bridge -> MQTT. AP-locked mode uses Wi-Fi MQTT, with USB available as another transport. Collector deduplication uses device/boot/sequence where supplied.

## Packet model contract

### Optional raw content metadata (2026-10-12)

Host packet messages add content_schema_version=1 and raw_tcp_payload_hex/text,
raw_http_query/uri/method/body, raw_mqtt_message/topic, raw_packet_info plus decoding,
field-type and capture-truncation metadata. They preserve dissector content before
categorical normalization; null denotes an absent raw field, literal 0 is retained.
These fields are not model inputs. Packet model schema/order remain unchanged.
Both live collector and Twin importer persist them. See
[raw application content](RAW_APPLICATION_CONTENT.md) for representations and
packet/reassembly/encryption limits. The 1 MB live message limit remains in force.

- `record_kind=packet`, `feature_semantics=edgeiiot-packet-v1`, `schema_version>=2`.
- Raw values for every entry in `ml_engine/config/schema.py::EDGE_IIOTSET_FEATURES`. Protocol-absent zero must differ from unmeasured fields; `missing_features=[]` is valid only for complete measurements. Numeric fields must be finite scalars.
- Preserve meanings: TCP payload length is not average frame length; UDP stream ID is not packet rate; checksum is not a boolean.
- Artifact preprocessing version 2. Extraction preserves categories; transform encodes/scales exactly once in saved feature order.
- Training eligibility additionally requires unique `packet_id`, `device_id`, epoch milliseconds, compatible capture backend, canonical label, and `label_source=manual_review` or `controlled_flow`. Since 2026-10-12, `label_verified` is deprecated and not a gate; old producer fields remain compatible. Automatic labels require flow attribution; anonymous MQTT does not establish trust.

The host TShark packet collector and Twin PCAP importer preserve this packet contract. ESP32 window telemetry remains a separate measurement contract; window fields are not fabricated into packet features. Label verification is an additional requirement, not implied by a complete feature vector.

## Unavailable prediction

```json
{
  "device_id": "ESP32-EdgeProbe-01",
  "timestamp": 42000,
  "inference_status": "unavailable",
  "error": "Window telemetry is incompatible with this packet-feature model; train a window model separately.",
  "is_anomaly": null,
  "anomaly_score": null,
  "severity": "UNKNOWN",
  "threat_type": "Unknown",
  "confidence": 0.0,
  "class_probabilities": {},
  "raw_telemetry": {}
}
```

Unavailable is not Normal and does not trigger an attack alert. Dashboard shows N/A/UNKNOWN. Successful compatible packet inference returns status ok, numeric score/confidence, authoritative anomaly decision and class probabilities. Prediction identity/timestamp refer to the source; receipt time is separate.

The collector persists raw packets independently of prediction callbacks. Raw Parquet
prediction fields remain unavailable; inference publishes separate results with `packet_id`
and `capture_id`. Predictions never become training labels.

## Runtime configuration

### Attack command acknowledgment and cancellation (2026-10-11)

`TRIGGER`, `STOP` and `AUTO_CYCLE` on `edge/attack/control` use QoS 1,
`retain=false`, and a unique `command_id`. The generator subscribes at QoS 1,
ignores retained commands, and deduplicates the latest 128 command IDs.
API responses report `accepted`; only the generator status acknowledging the
same `command_id` confirms application. The frontend reports an acknowledgment
timeout after 10 seconds. Backend and generator must both be restarted for this
contract update.

A manual trigger disables Auto-Cycle, wakes its waiting thread, cancels the
previous burst, and selects the requested canonical scenario. Normal/STOP cancels
the current workload and disables Auto-Cycle. Sends/connections already in progress
finish within their socket timeout; queued operations check cancellation before
starting. No attack starts when the UI opens. A retained `ATTACKING` status whose
`expires_at_ms` is missing or expired is displayed as stale, not active.

Data-lake summary counts only catalog batches whose Parquet files still exist.
Deleting `raw/` leaves catalog history intact but excludes deleted batches from
displayed totals. An active collector can recreate `raw/` with newly captured data.

Root `.env` is loaded by `run_system.py`; `.env.example` lists survey credentials, broker address/port and host interfaces. Environment overrides `.env`; CLI broker flags override those values. ESP32's ignored `credentials.h` is generated for compilation: changed credentials require build/flash. `AUTO_DETECT_WIFI` and `MQTT_AUTO_DISCOVERY` default false. See `DATA_HEALTH_AND_COLLECTION_REVIEW.md` for deployment limits and validation.

### Twin experiment collection (2026-10-11)

The dashboard scenario buttons now use `POST /api/experiments/start` with
`{"scenario":"Normal","duration_sec":15}`. `POST /api/experiments/stop` requests
cooperative cancellation; `GET /api/experiments/status` reports progress. Accepted
commands are not completed captures. One session can run at a time. Normal starts
a measured HTTP workload; it no longer means STOP in this UI. The legacy
`edge/attack/control` contract above remains available to its existing consumers.

`edge/experiments/status` publishes informational status at QoS 1 with
`retain=true`: `schema_version`, `experiment_id`, `command_id`, `scenario`,
`phase`, `timestamp`, capture counters, and error context where applicable.
Phases are STARTING, RUNNING, IMPORTING, COMPLETED, or ERROR. Retained status is
historical information and never starts a workload. The frontend also receives
`EXPERIMENT_STATUS_UPDATE` over WebSocket; MQTT delivery is not required for the
local experiment worker to persist its capture.

Packets follow dumpcap PCAPNG → offline TShark extraction → Parquet, independently
of the live MQTT packet queue. Ground truth uses matching bidirectional flows and
timestamps. Normal keeps HTTP response checks for service health. Both Normal and
attack labels use `label_method=automatic_flow`, `label_source=controlled_flow`.
New Twin rows/status omit `label_verified`/`verified_rows`; training ignores old
flags. Status schema version is 2. Unattributed packets remain Unknown. Capture
now filters TCP/UDP on the lab service port for every scenario, excluding broad
loopback background and ICMP. See
[Twin experiment guide](TWIN_EXPERIMENT_COLLECTION.md) for configuration,
capture limits, manifests, and validation scope.
# Twin experiment metadata v3

PCAP-imported rows retain `ground_truth_scenario`/`label_source=controlled_flow`;
`scenario_version`, `scenario_fidelity`, `supervised_training_eligible`,
`experiment_manifest_version=3` and `capture_environment` describe collection.
These are metadata, excluded from canonical model inputs. Surrogates and pre-v3
Twin attack records are excluded from training by the quality gate; no manual
verified flag is required. ICMP echo attribution additionally uses measured
`icmp_identifier` and `icmp_type`, never quoted TCP/UDP headers in ICMP errors.

Windows raw SYN/ICMP experiments use an isolated Linux container and import PCAP
on the host. They currently send experiment status on `edge/experiments/status`,
not a live container telemetry stream; the ordinary host live probe is separate.

# Twin surrogate metadata v4

Fingerprinting, MITM, Backdoor and Ransomware now use isolated container experiments.
New rows carry `experiment_manifest_version=4`, `scenario_version=twin-workloads-v4`,
`training_domain=controlled-surrogate-lab`, `evidence_contract`, and `fixture_effect_ok`.
Only an attributable flow with successful scenario-specific effect may have
`supervised_training_eligible=true`. Status starts with eligibility false (pending),
then reports successful eligibility at COMPLETED; per-row training checks still
reject unproven flows. Older surrogate rows remain excluded. These fields are audit
metadata, never model features. Capture still uses container loopback; no live
container inference/MQTT packet telemetry is implied by experiment status.
See [surrogate v4 guide](TWIN_SURROGATES_V4.md).
