# ESP32 model conversion and RF/IF demos

## Can the chip collect all 56 fields?

The 56 names are a schema, not 56 independent radio measurements. A bounded
firmware dissector can implement the corresponding protocol fields when the input
is available. It needs IP/TCP reassembly, per-flow relative sequence/stream state,
DNS retransmission tracking and HTTP/MQTT/Modbus parsers. Exact TShark parity also
requires matching dissector version, preferences, field occurrence and supported
capture conditions. Nothing in this change claims that a TShark-equivalent
56-field extractor is already implemented on ESP32.

Encrypted or missing bytes cannot be reconstructed just by choosing a larger ML
model. TShark itself needs appropriate keys for decryption and enough captured
segments for reassembly. TLS application encryption and Wi-Fi link encryption are
separate restrictions. Promiscuous-mode traffic is not automatically decrypted
because the probe joined the AP. Current live firmware implements ten numeric
ARP/ICMP/TCP fields and explicitly marks unsupported/missing input unavailable.

Measurement work can be expanded protocol by protocol, using bounded flow state
and TShark parity fixtures. A full model can already be converted independently of
that capture work, and the full conversion is provided below.

## Public conversion functions

`ml_engine/exporter/esp32_model_exporter.py` exposes:

- `export_model_header(...)`: fitted classifier, detector, scaler, feature/label
  order and metadata -> standalone C/C++ tables and a resource manifest.
- `export_classifier_to_esp32(...)`: DecisionTreeClassifier, RandomForestClassifier,
  ExtraTreesClassifier or LogisticRegression. RF/ExtraTrees average the full leaf
  probability distributions of **every** tree, as sklearn does.
- `export_anomaly_to_esp32(...)`: IsolationForest, RBF OneClassSVM or EllipticEnvelope.
  IF exports **every** tree, feature-subset mappings and correct leaf path lengths.

The numeric interface is `esp32_preprocess(...)` and
`esp32_predict_packet(raw, probabilities, anomaly_score, score_sample)`. Here
`raw` means **unscaled encoded numeric features in fitted order**, not arbitrary
strings or raw packet bytes. StandardScaler parameters and float32 operations are
exported. Unsupported models, incompatible dimensions, oversized trees and
resource-budget failures raise explicit errors; no tree truncation, substitute
classifier or Normal fallback is used. The budget counts numeric constant arrays,
not complete firmware flash/RAM or linker alignment.

Raw string encoding is a separate fitted preprocessing step. The added
`EdgeTrafficPreprocessor.encode_features()` returns exactly that step before
scaling and is shared with the ordinary runtime transform. Full raw categorical
vocabularies are not embedded in the generated C header. DNN/TFLite export remains
in the existing separate modules; it is not asserted equivalent by this exporter.

## Demo bundles generated in this workspace

| Bundle | Input | Trees exported | Numeric constant bytes | Native parity |
|---|---|---|---|---|
| `ml_engine/models/esp32_rf_if_56_demo` | Prepared, encoded 56-field vectors | RF 100 + IF 100 | 5,592,422 (~5.33 MiB) | 120 vectors across 15 classes |
| `ml_engine/models/esp32_rf_if_packet_demo` | Live ten-field native packet profile | RF 16 + IF 8 | 213,316 (~208 KiB) | 141 representative vectors |

The full bundle converts the existing trusted
`random_forest_isolation_forest` artifact without retraining or overwriting it.
Source artifact SHA-256 identities and sklearn 1.6.1 are recorded. Conversion
references were computed using that original version, isolated from the existing
validation environment. Its numeric arrays alone exceed nominal 4 MiB flash;
even a larger-flash board needs linker/mapped-memory and application partition
verification. Its raw vocabulary has another **28,450,972 UTF-8 bytes (~27.13 MiB)**,
excluding lookup indices/pointers. A header accepting encoded vectors does not
solve that raw categorical encoding footprint.

The compact RF was trained offline on the same documented benchmark profile and
group-disjoint split as the earlier DT prototype, using a seed and fixed tree
budget. It is a separate artifact, not a truncated copy of the full RF. The split
was already inspected during the DT prototype, so this is a comparative demo,
not a fresh independent benchmark. Classifier macro F1 is **0.646113**, while
the final gated alert pipeline macro F1 is **0.047399**. The low gated recall and
unmeasured radio/hardware performance remain limitations; the artifact is marked
`deployment_ready=false`. Do not substitute the full classifier's metrics for it.

The compact generated header has been copied to
`firmware/esp32_probe/esp32_packet_model.h` after native parity succeeded. Firmware
model names come from the generated header, so Serial/UI identify Random Forest
rather than a hardcoded Decision Tree. The live extractor remains ten fields;
compile-time checks and deployment validation reject a 56-field header for this
extractor.

## Running the demos

`firmware/esp32_rf_if_demo/` is an independent Arduino sketch with prepared dataset
vectors. It executes scaler/RF/IF locally and prints class probabilities, gate
decision and measured `latency_us` when run on the board. It clearly announces
**SIMULATED INPUT DEMO**: it neither captures traffic nor proves attack detection.

Compile this sketch for the actual installed board/core, for example the existing
launcher board target:

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_rf_if_demo
```

No board compilation or upload was performed here: arduino-cli/toolchain is not
available. Actual flash/RAM, serial behavior and latency still require hardware
validation. Compilation is separate from upload.

For the updated live probe firmware, compile/flash it separately, then:

```powershell
python run_system.py --probe esp32 --port COMx --no-tshark --models-dir ml_engine/models/esp32_rf_if_packet_demo
```

Model weights are not retrained or replaced by launching the system.

## Reproduction

To convert an existing trusted full artifact, use its compatible Python/sklearn
environment and a fresh output directory:

```powershell
python -m ml_engine.edge.export --models-dir ml_engine/models/random_forest_isolation_forest --output ml_engine/models/full_export_new
python -m ml_engine.edge.validate_export --bundle ml_engine/models/full_export_new --compiler PATH_TO_ZIG
```

For a new compact RF/IF bundle:

```powershell
python -m ml_engine.edge.train --classifier random_forest --trees 16 --output ml_engine/models/compact_rf_new
python -m ml_engine.edge.validate_export --bundle ml_engine/models/compact_rf_new --compiler PATH_TO_ZIG --deploy
python -m ml_engine.edge.demo --bundle ml_engine/models/compact_rf_new --output firmware/esp32_demo_new
```

Native export regression tests cover DT/RF/ExtraTrees/LogisticRegression (binary
and multiclass), IF/RBF-SVM/EllipticEnvelope, explicit unsupported-model rejection
and failure without truncation on memory-budget overflow. All probability vectors,
scaled inputs, anomaly scores, winning classes and threshold decisions are checked
against Python with `rtol=2e-6`, `atol=2e-6`. Native x86 execution is not ESP32
hardware validation or a reproduction of benchmark accuracy.

References: [Wireshark reassembly/decryption](https://www.wireshark.org/docs/wsug_html/),
[Espressif sniffer callback context](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32/api-guides/wifi.html),
[sklearn forest probability semantics](https://scikit-learn.org/1.8/modules/generated/sklearn.ensemble.RandomForestClassifier.html).
