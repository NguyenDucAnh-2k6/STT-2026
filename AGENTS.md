# Agent Instructions for AERO

## Scope and working principles

These instructions apply to this repository. Follow explicit user instructions first and read any more specific `AGENTS.md` in the directory you change. Use this file as engineering guidance, not as evidence that existing code already satisfies every rule.

AERO monitors network traffic, performs host and ESP32 edge inference, exchanges telemetry and control messages over MQTT, and exposes a Python FastAPI dashboard. It also contains offline ML training, a Parquet/SQLite data lake, and experimental Digital Twin, GAN, and reinforcement learning components.

- Inspect the relevant implementation and `git status` before editing. Preserve existing user changes, including untracked files. Avoid unrelated refactoring, renaming, or formatting.
- Keep changes within the requested scope. Report defects discovered outside that scope rather than silently rewriting the project.
- Distinguish measured behavior, simulated behavior, implemented capabilities, and planned capabilities in code, documentation, and reports.
- Documentation can lag behind implementation. Check entrypoints, schemas, and artifact metadata before relying on README claims about feature counts, accuracy, latency, or hardware support.
- Keep these instructions in English. Preserve existing Vietnamese user-facing text and document names unless the task asks to change them.

## Repository organization

| Location | Responsibility |
| --- | --- |
| `run_system.py`, `run_system.bat`, `run_system.sh` | Runtime orchestration and platform launch wrappers. Runtime inference must not implicitly train models. |
| `train.py` | Thin root wrapper for the offline training CLI in `ml_engine/train.py`. |
| `launcher/` | Host network discovery, background workers, USB serial telemetry bridging, and ESP32 compilation/flashing helpers. |
| `firmware/esp32_probe/` | Arduino C++ sketch and modules for sniffing, edge inference, MQTT, OLED, and LED/buzzer output. |
| `firmware/host_probe/` | Host capture and TShark extraction. Separate packet measurements from fallback estimates. |
| `firmware/simulator/` | Controlled traffic generation. Some scripts send real network traffic. |
| `broker/` | Broker discovery/selection, embedded development broker, Mosquitto configuration, and Docker Compose. |
| `ml_engine/config/schema.py` | Canonical feature names/order, labels, telemetry types, and shared ML constants. |
| `ml_engine/preprocessing/` | Dataset loading, feature extraction, protocol-specific transforms, encoders, scaling, and time-series windows. |
| `ml_engine/algorithms/` | Classifier and anomaly detector implementations behind shared interfaces. |
| `ml_engine/tuning/` | Offline hyperparameter optimization and cross-validation. |
| `ml_engine/exporter/` | Generated C/TinyML/TFLite export logic. `export_tinyml.py` is an export entrypoint. |
| `ml_engine/eda/`, `ml_engine/notebooks/` | Exploratory analysis, drift analysis, notebooks, and diagnostic figures. |
| `ml_engine/adversarial/` | Offline GAN training and adversarial evaluation. |
| `ml_engine/datasets/`, `ml_engine/models/` | Datasets and per-model artifacts; not general-purpose source directories. |
| `dashboard/backend/` | FastAPI app/lifespan, Pydantic models, configuration, runtime state, MQTT bridge, WebSocket manager, and routers. |
| `dashboard/frontend/` | Static HTML/CSS and native JavaScript ES modules: shared state, services, and UI components. |
| `data_lake/` | Telemetry collection, Parquet persistence, SQLite catalog, and optional S3-compatible synchronization. |
| `digital_twin/` | Simulation models/engine, live synchronization, RL policy, safety validation, network enforcement adapters, and isolated lab testbed (`digital_twin/lab/`). |
| `docs/` | Proposal and architecture/API/hardware documentation. The proposal is `docs/Sáng tạo trẻ.docx`. |
| `Literature/` | Research references, not application code. |
| `scratch/` | One-off investigation scripts and intermediate analysis. Production code must not depend on it. |
| Root `test_pipeline.py` | Existing limited inference/MQTT smoke test; inspect its coverage before calling it end-to-end validation. |
| Root `test_traffic_generator.py` | Real traffic generation utility despite its name; not an isolated unit test. |
| Root `view_parquet.py`, spreadsheets, and `output.csv` | Analysis utilities and working artifacts; keep them outside runtime dependencies. |

Put new code in the component that owns its behavior. Keep CLI wrappers thin, API routers focused on validation/orchestration, and business logic independently testable. Avoid duplicating preprocessing or decision logic in the dashboard, launcher, or frontend. Add focused tests under `tests/` for new regression coverage; do not move existing scripts merely to enforce this layout.

Treat `tinyml_model.h`, `tinyml_tflite_array.h`, trained weights, metadata, and exported figures as generated artifacts. Fix their generator or source configuration and regenerate the relevant bundle; do not patch model coefficients or decision trees by hand. Keep model-directory and deployed firmware copies consistent. Do not overwrite existing models, datasets, captures, proposal documents, or analysis artifacts as an incidental validation step.

## Naming and formatting

- Python: `snake_case` modules/functions/variables, `PascalCase` classes, `UPPER_SNAKE_CASE` constants, and `test_*.py` for actual automated tests.
- ESP32 C++: preserve the existing `snake_case` filenames and `lowerCamelCase` functions; use `PascalCase` types and `UPPER_SNAKE_CASE` macros/constants. Pair interfaces in `.h` with implementations in `.cpp`; use include guards or `#pragma once`.
- Future POSIX C modules: `snake_case` functions/files, explicit ownership in API documentation, and standard `.c`/`.h` pairs. Do not introduce POSIX APIs into ESP32 firmware without a demonstrated platform requirement.
- Frontend: `snake_case` filenames, `camelCase` variables/functions, and `PascalCase` classes. Keep the native ES module structure unless a build-system change is requested.
- Preserve established MQTT topics, JSON field names, label spellings, and feature names as public contracts. Internal naming conventions do not justify changing `Attack_type`, `tcp.len`, or other external dataset fields.
- Use UTF-8. Python uses four-space indentation; firmware and frontend changes follow surrounding indentation. Do not reformat generated model headers.
- Include units in names for new numeric fields, such as `latency_ms`, `timeout_sec`, or `byte_rate`. Document existing fields whose units are implicit.
- Use repository-relative paths resolved from the module/repository location, or explicit configuration. Do not hardcode developer-specific drive letters or home directories.

## Python and FastAPI standards

- Target the project's documented Python 3.10+ baseline unless explicitly changed. Add type hints to new or materially changed function parameters and return values, including `-> None` where appropriate.
- Use Pydantic models for external API payloads and typed structures/dataclasses for internal records. Reserve `Any` for genuinely heterogeneous boundaries; validate immediately after decoding them.
- Use explicit package imports. Keep unavoidable script-entrypoint path setup confined to entrypoints rather than spreading `sys.path` mutations through library modules.
- Keep import-time behavior limited to definitions and lightweight configuration. Do not start threads, connect to MQTT, modify firewalls, train models, or write artifacts merely by importing a module.
- Manage service startup/shutdown through explicit lifecycle methods; use FastAPI lifespan for backend resources. Cleanup must also work after partial startup failure.
- Never block the asyncio event loop with training, synchronous cloud transfers, heavy inference, file I/O, or subprocess waits. Offload blocking work to an appropriate worker or executor with bounded concurrency.
- MQTT callbacks may run in a different thread. Transfer updates to the owning event loop using a thread-safe queue or scheduling API, or synchronize shared state explicitly. Scheduling a WebSocket broadcast alone does not make earlier state mutations thread-safe.
- Bound histories, queues, and per-client buffers. Apply timeouts and disconnect or shed slow WebSocket consumers so one client cannot stall telemetry delivery.
- Use structured logging with component, device/session ID, operation, and error context. Do not log credentials or raw sensitive payloads.
- Declare required imports in dependency manifests. Keep optional ML/export/cloud dependencies lazy and provide actionable installation errors. Do not require unrelated optional frameworks for basic runtime inference.

## Threads, processes, and POSIX C

The current host services primarily use Python threads/processes; ESP32 uses Arduino/FreeRTOS. Apply the POSIX-specific rules below only when adding or modifying native host C modules.

- Give every worker an owner, explicit stop mechanism, timeout policy, and deterministic cleanup. Prefer cooperative cancellation to daemon-only lifetime management or forced termination.
- In Python, use events/queues for coordination, protect compound shared-state operations, and join owned workers with bounded waits. Guard multiprocessing entrypoints for Windows spawn compatibility.
- Track and stop only processes started by this application. Do not terminate all processes sharing a name, such as every `tshark.exe` on the machine.
- Use subprocess argument arrays with `shell=False`. Validate IPs/MACs/ports and other external parameters before passing them to platform tools. Drain redirected output or use `communicate()` to avoid pipe deadlocks.
- In POSIX C, check system call and `pthread_*` return values. `pthread_*` functions return their error code directly; do not assume it is stored in `errno`.
- Document buffer/file-descriptor ownership, protect shared state with mutexes/atomics, establish lock ordering, and wait on condition variables in predicate loops. `volatile` is not synchronization.
- Keep POSIX signal handlers async-signal-safe: set a `sig_atomic_t` flag or notify a self-pipe. Do cleanup, logging, allocation, and locking outside the signal handler.
- Prefer controlled `posix_spawn`/`exec` paths over shell commands. Avoid unsafe work between `fork()` and `exec()` in multithreaded processes. Reap child processes with `waitpid()` and handle interrupted calls, partial reads/writes, EOF, and bounded retries.
- Close sockets, serial ports, files, MQTT loops, and SQLite connections on every exit path. Never hold shared locks across slow I/O or wait for a worker while holding a lock it needs.

## ESP32 C++ and memory constraints

- Keep the Wi-Fi receive callback short and bounded. Do not perform inference, MQTT publishing, JSON serialization, display updates, blocking waits, or heap allocation in it. Move work to the main loop or a dedicated task through bounded storage.
- Follow the callback's actual ESP-IDF execution context. Do not assume every `IRAM_ATTR` function is an ISR; select task/ISR-safe synchronization accordingly.
- Protect shared counters, port bitmaps, and network records across callback and consumer contexts with suitable FreeRTOS/ESP-IDF primitives. Snapshot-and-reset must be atomic with respect to updates; disabling interrupts on one core or marking fields `volatile` alone does not establish cross-core safety.
- Prefer fixed-capacity buffers and fixed-width integers. Check packet lengths before every header access, validate offsets/header lengths, and reserve space for string terminators. Never retain pointers into driver-owned packet memory after the callback returns.
- Avoid repeated Arduino `String` concatenation and dynamic allocation in hot paths. Keep model constants read-only and use flash-backed storage appropriate to the target/toolchain.
- Size JSON documents, MQTT buffers, queues, and task stacks deliberately. Check serialization/publish failures and truncation; account for worst-case payload sizes and expose dropped-packet/message counters.
- Check counter overflow and wrap-safe `millis()` arithmetic. Use monotonic elapsed time for windows, timeouts, and latency measurements.
- Do not infer unavailable TCP/UDP/application content from encrypted Wi-Fi frames. Label capture limitations and estimates; never present a fabricated port, checksum, sequence number, or payload as a measurement.
- Preserve local inference and local alert operation during transport outages. Reconnection work must not indefinitely block sampling or the watchdog.
- Keep hardware settings in `config.h` and local secrets in ignored `credentials.h` created from `credentials.h.example`. Do not embed real Wi-Fi passwords in tracked code.
- Compile against the intended board/core/library versions and report flash/RAM usage when changing model size, buffers, or task stacks. Do not invent latency or memory guarantees without measurements on the specified hardware.

## MQTT and cross-component contracts

- Consult `docs/MQTT_API_SPEC.md`, `ml_engine/config/schema.py`, and current producers/consumers together. Update affected documentation and compatibility handling when a contract changes.
- Existing topic families include `edge/telemetry/traffic`, `edge/telemetry/prediction`, `edge/alerts/high_priority`, `edge/nodes/status`, `edge/attack/control`, `edge/attack/status`, and `edge/config/threshold`. ESP32 local alerts currently use `edge/alerts/high_priority`. Verify exact names at each call site; do not silently create a parallel topic.
- Validate payload size, JSON shape, types, finite numeric values, bounds, timestamps, and required identifiers. Add explicit schema/model versions when evolving payloads. Define timestamp units and timezone semantics.
- Define QoS, retention, reconnect behavior, and duplicate handling per message type. Do not retain commands that could be replayed as fresh attack or enforcement requests. Use IDs/acknowledgments for commands whose application matters.
- Treat all telemetry and control inputs as untrusted. Authenticate control APIs and protect command topics with broker ACLs for deployment beyond an isolated development environment; use TLS where required by the deployment.
- Keep observed telemetry, ground-truth labels, model predictions, and operational health in separate fields. Identify probe source, measurement capability, and whether values are measured, estimated, or simulated.
- Display authoritative inference/threshold versions consistently. Do not silently relabel host or edge results in a UI bridge using a different threshold.

## Digital Twin Lab and synthetic attack workloads

- Organize attack scenario generators into modular domain packages under `digital_twin/lab/scenarios/` (`ddos.py`, `web.py`, `recon.py`, `surrogates.py`). The facade `TwinWorkloads` in `digital_twin/lab/workloads.py` dispatches cleanly via `dispatch_scenario()` and must retain its established public methods (`burst`, `request`, `http`).
- Preserve backward-compatible entrypoints: do not break external consumers importing from `digital_twin.lab.workloads`, `raw_packets`, `controlled_channel`, `flows`, or `services`.
- Enforce loopback and container isolation: all lab traffic generators must target only allowed loopback addresses (`127.0.0.1`, `127.0.0.2`) and owned lab ports. Never connect or send raw packets to external or LAN hosts.
- Isolated container compatibility: code running inside the Docker lab container (`--network none`) must never assume functional external DNS resolution. Always guard hostname/broker lookups with safe fallbacks and explicit try/except blocks.
- Bounded and disposable execution: every workload burst must respect cancellation tokens (`cancel.is_set()`), run bounded iterations/durations, and deterministically tear down temporary files, sockets, and in-memory databases.
- Surrogate contract integrity: controlled surrogates (`Backdoor`, `Ransomware`, `MITM`, `Fingerprinting`) must verify explicit effects (`fixture_effect_ok`, `evidence_contract`) before setting `supervised_training_eligible=True`. Never mark unobserved or failed simulations as valid training data.
- Do not execute real exploit payloads, shell commands, or destructive malware: web payloads must be inert/contained, and encryption surrogates must operate only on temporary test files with reversible keys.

## ML correctness and data leakage prevention

These requirements apply to supervised learning, anomaly detection, Optuna, GAN evaluation, and RL evaluation where relevant.

1. Split raw records into train/validation/test before fitting preprocessing. Fit scalers, imputers, normal baselines, encoders, feature selection, and learned transforms only on training records.
2. For cross-validation, fit preprocessing independently inside each fold. Perform hyperparameter search, early stopping, threshold calibration, and model selection using training/validation data, never the final test set.
3. Keep sessions/flows/devices or environments disjoint when records are correlated. Use chronological splits for time-series evaluation and build windows after splitting; prevent overlapping windows across split boundaries and future-data use in rolling features.
4. Exclude labels, simulator scenario/status, downstream predictions, and identifiers that encode the answer from model inputs. Audit endpoint IDs, timestamps, payload artifacts, and duplicate records for shortcuts and contamination.
5. Fit anomaly detectors on verified normal training data. Unlabeled traffic is not automatically normal. Label real captures using attributable flows/events; a global simulator status is not ground truth for every concurrent packet or probe.
6. Keep synthetic and real data provenance explicit. A missing benchmark must fail clearly or enter an explicitly requested synthetic mode; do not silently train on generated data and report it as benchmark performance.
7. Encode categorical values exactly once. Training, runtime extraction, and firmware export must preserve identical feature order, units, aggregation windows, missing-value semantics, category mappings, scaling, and label order.
8. Do not substitute a convenient quantity for a feature with a different meaning: packet rate is not a stream ID, a boolean is not a checksum, and total frame length is not necessarily TCP payload length. Retrain on the features the target probe can actually measure.
9. Test the final alert pipeline, including anomaly gating and classifier decisions, rather than only the classifier. Report per-class precision/recall/F1, macro F1, false alarms per time interval, detection delay, and appropriate anomaly metrics with dataset/split context.
10. Preserve measured results exactly. Zero is a valid F1 score. Failed or unavailable evaluation must be `null`/unavailable with an explanation, never a plausible hardcoded accuracy/AUC/F1.
11. Record seeds, dataset provenance/fingerprint, split strategy, preprocessing version, feature/label order, algorithm parameters, dependency versions, and evaluation artifact identity. Seed each relevant library and document remaining nondeterminism.
12. If refitting on all available data for deployment, distinguish that artifact from the one evaluated on a held-out set. Do not claim that a deployment artifact trained on the test set was independently tested on that same set.

Changing canonical features requires coordinated changes to extraction, training, metadata, export, and firmware. Add Python-versus-C prediction/vector parity checks with representative inputs and explicit tolerances before calling an export equivalent.

## Error handling, privacy, and enforcement

- Catch expected exceptions at clear boundaries. Broad catches are acceptable only at service boundaries with logging, an explicit degraded/error state, and a defined recovery path. Avoid silent `except: pass` for operations that affect correctness.
- An inference exception must not become `Normal`, `is_anomaly=False`, or an apparently safe score. Return a distinct unavailable/error status and expose service health independently from threat severity. NaN/Inf scores are errors, not valid normal decisions.
- Missing, incompatible, or corrupt model artifacts must stop inference startup or expose a clear unavailable state. Validate feature count/order, preprocessing identity, and model compatibility before accepting telemetry.
- Report startup failures, disconnected brokers, stale probes, capture failures, dropped messages, and persistence errors. Retry transient failures with bounded backoff; do not suppress permanent configuration errors indefinitely.
- API responses must distinguish accepted commands from acknowledged/executed actions. Check publish results and downstream acknowledgments where needed; do not return success for an unimplemented operation.
- Keep real firewall/network enforcement opt-in and simulation clearly marked. Validate targets, require attribution to the suspicious flow/source, protect configured management infrastructure, and reject unknown targets rather than substituting a hardcoded IP.
- Network actions need explicit supported/unsupported outcomes, audit records, reversible leases, and verified cleanup. Keep failed rollback actions tracked for retry; do not claim firewall/QoS/deauthentication changes based only on a log line.
- Never commit or echo `.env`, local firmware credentials, tokens, cloud keys, or private connection details. Use sanitized examples.
- Packet payloads, IP/MAC addresses, SSIDs, HTTP content, and capture files can contain sensitive data. Collect only what the task needs; redact reports/logs and make remote upload/retention explicit. Avoid placing raw sensitive captures in source-controlled fixtures.
- Persist data atomically where practical, protect catalog consistency, and flush owned buffers during shutdown. Load serialized Python models only from trusted sources; joblib/pickle loading can execute code.

## Validation and completion

- Run focused, deterministic checks for changed behavior. Use mocks or isolated local services for MQTT, capture, cloud storage, subprocesses, and firewall operations. Add regression tests for substantive correctness fixes, especially leakage, encoding parity, inference errors, and lifecycle races.
- Documentation-only changes require content/path/format review, not model retraining or a full system launch.
- The repository does not currently define a universal lint/test pipeline. Do not claim a command exists without checking. New isolated tests can use standard-library `unittest`; introduce other tooling only with an appropriate dependency/configuration change.
- `python test_pipeline.py` requires available model artifacts and starts a local broker on port 1883. It performs direct inference and publishes results itself, so it does not prove the telemetry-to-inference subscriber path works. Check port isolation and model assumptions before running it.
- Do not include `test_traffic_generator.py` in automatic test discovery or run it as a routine check: it can scan/flood a real target. Likewise, avoid incidental `--attack-sim`, `--flash`, `--enforce-real-network`, cloud push/pull, or credential auto-discovery during unrelated validation.
- Firmware compile checks may use `arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_probe` for the current launcher board target, if the required toolchain/libraries are available. Select the actual target for other boards. Compilation is separate from uploading firmware.
- Report what changed, which checks ran, their results, and any remaining limitations. Separate syntax checks, offline inference, simulated integration, and physical hardware validation. Never claim hardware validation, full end-to-end coverage, or benchmark reproduction without performing it.
