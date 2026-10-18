# ESP32 Edge AI: implemented prototype

The current RF/IF demo and generalized classical exporter are documented in
[ESP32 model conversion](ESP32_ML_EXPORT.md). The live firmware header now uses
RandomForestClassifier + IsolationForest. The DT results below describe the
earlier retained `esp32_packet_v1` artifact, not the new RF demo's accuracy.

ESP32 can execute trained preprocessing and inference. The previous radio pipeline
sent frames to host TShark; naming its output columns canonical did not make the
ESP32 a 56-field dissector. This implementation adds a local bounded parser and
an explicit model profile: `esp32-l234-packet-v1`.

## Local computation

`packet_features.cpp` extracts ten canonical raw integer measurements:
`arp.opcode`, `arp.hw.size`, `icmp.checksum`, `tcp.ack_raw`, `tcp.checksum`,
`tcp.dstport`, `tcp.flags`, `tcp.flags.ack`, `tcp.len`, `tcp.srcport`.
Raw integers are retained exactly, including large TCP acknowledgment values.
The model converts the vector to float32, applies the learned StandardScaler,
traverses a DecisionTree and every tree of a compact IsolationForest, normalizes
the detector score and applies the device's current threshold. Class distributions
come from actual tree leaves. No HTTP/MQTT categories or window statistics substitute
for these packet fields.

Supported input is complete unprotected ARP, IPv4 TCP, or ICMP echo/timestamp
frames with ordinary LLC/SNAP encapsulation. Protected/truncated/fragmented frames,
A-MSDU, IPv6, UDP-only packets and ICMP errors with quoted inner headers are
unavailable for this first profile. Protocol-absent zeros are valid within a
supported packet; a wholly unsupported packet cannot become a zero-vector Normal.
Other canonical features remain null in the native lake view.

Computation occurs in the Arduino loop after copying from the bounded Wi-Fi
callback queue. LED/buzzer state follows the local decision before transport.
It works without host inference or MQTT connectivity; reconnection still has a
bounded WiFiMulti wait and can delay samples. Results expire after five seconds.
The radio sample interval is 750 ms to leave USB bandwidth for probabilities and
windows. This interval is a sampling limit, not measured detection latency.
When MQTT is available the firmware also sends one packet-level local alert on
`edge/alerts/high_priority`. USB-forwarded alerts use the same native packet ID;
the dashboard deduplicates device/bridge copies with a bounded identity history.

## Host role and transport

Radio messages carry `edge_input_profile`, artifact ID, measured raw features,
status/error, score, threshold, confidence, class probabilities and inference
latency measured on the chip when it runs. Python validates and forwards the device
result. It does not load host models, recompute scores or apply a different threshold
in `--probe esp32` mode. MQTT and USB copies are deduplicated by device/boot/sequence.
Probability bars therefore reflect the ESP32's classifier when valid.

The bridge publishes native packet rows to `edge/telemetry/traffic`, with
`capture_backend=esp32_native`, profile semantics and stable `:native:` IDs.
The ten measured columns are preserved; the other 46 canonical fields are null.
These packets are collected independently of predictions and have unknown labels.
They are not accepted as complete 56-feature training records.

Host TShark is optional enrichment. It publishes a separate `esp32_tshark` view
with `:radio:` IDs and its wider dissector fields. These views must not be counted
as two independent observed frames. Dashboard counts use cumulative radio-window
counts. `--no-tshark` disables this enrichment without disabling local inference
or native feature persistence. Live Twin and its experiment worker remain disabled.

After compiling/flashing the new firmware for the intended board:

```powershell
python run_system.py --probe esp32 --port COMx --no-tshark
```

## Offline training, export and measured limitations

`ml_engine/edge/train.py` trains a separate artifact on the real local Edge-IIoTset
CSV. Original model bundles are retained. Raw flow groups are disjoint across
train/validation/test; flows sharing identical projected vectors are merged so
identical inputs cannot cross split boundaries. Scaler and classifier fit only
training rows, IsolationForest fits labeled normal training rows, and threshold
calibration uses normal validation rows. Endpoint identities remain split metadata,
never model inputs. The fixed artifact is not refit on the test set.

The current split has 92,585 train, 25,541 validation and 30,771 test rows.
Measured classifier macro F1 is **0.607789**. The final gated pipeline macro F1,
including the separate ZeroDay outcome, is **0.048095**; detector ROC AUC is
**0.691240** and normal false-alarm fraction is **0.008800**. Some classes have
zero recall, and MITM has no test support. This artifact is an experimental
computation prototype, **not a deployment-ready detector**. In particular the
normal-calibrated anomaly gate suppresses most classifier detections. These
results must not be replaced by the original 56-field model's benchmark claims.
Time-interval false alarms and detection delay are unavailable for this CSV split.
Physical radio-domain accuracy remains unmeasured.

The new exporter includes every fitted tree and full leaf probability distribution,
correct IsolationForest leaf path lengths/feature mappings, and scaler precision.
It avoids the older generic exporter's tree truncation/weighted winning-class vote.
Those older bundles were not rewritten or declared equivalent to their host models.

Reproduce into a new artifact directory; training refuses to overwrite one:

```powershell
python -m ml_engine.edge.train --output ml_engine/models/esp32_packet_new
python -m ml_engine.edge.validate_export --bundle ml_engine/models/esp32_packet_new --compiler PATH_TO_ZIG --deploy
```

Deployment copies the generated header only after native parity succeeds. The
current header matches its model-directory copy. Native checks use 141 held-out
vectors across available classes and feature extrema. Scaling, all probabilities,
detector scores, winning classes and threshold decisions agree within `rtol=2e-6`,
`atol=2e-6`; maximum scaling error is about `4.77e-7`, maximum normalized score error
about `2.94e-8`. Synthetic ARP/TCP/ICMP parser vectors match TShark, including uint32
ACK precision; malformed/protected/truncated/fragmented inputs are rejected.

This is native C++ validation, not an ESP32 board/core compile or physical benchmark.
Arduino toolchain compilation, board flash/RAM consumption, watchdog behavior,
offline LED/buzzer operation and actual latency still require board validation.

References: [Espressif Wi-Fi callback guidance](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi-driver/wifi-modes.html)
and [IsolationForest score semantics](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).
