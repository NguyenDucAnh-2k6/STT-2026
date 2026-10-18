# ESP32 radio collection and inference

**Current local inference:** see [ESP32 Edge AI](ESP32_EDGE_AI.md). The firmware
now extracts ten canonical numeric features and executes its own exported model.
Python forwards device probabilities/decisions; TShark is optional enrichment.
Use `--no-tshark` for native-only collection/inference. The details below retain
the wider TShark capture contract and its limits.

`python run_system.py --probe esp32 --port COMx --no-browser` starts the
broker, lake collector, packet inference, dashboard and radio decoder. Replace
`COMx` with the actual port; omit it for Wi-Fi-only transport or automatic USB
detection. Install the project's Python dependencies and Wireshark/TShark first.
Flash the updated firmware separately; launching does not upload it. The optional
existing `--arduino-cli` flag explicitly requests compilation/upload.

ESP32 mode does not start Live Digital Twin, RL defense, or the dashboard Twin
experiment service. It does not generate attack traffic unless `--attack-sim` is
explicitly supplied. Existing host mode behavior remains unchanged.

## Implemented pipeline

1. The Wi-Fi driver callback counts observed frames and copies sampled data frames
   into a fixed four-slot ring, each holding at most 2048 bytes. FCS is removed.
   Serialization and transport happen in the Arduino main loop. The default minimum
   sample interval is 750 ms to fit the 115200 baud USB transport. This is sampled
   radio traffic, not an exhaustive packet capture. `radio_sample_skipped` and
   `radio_queue_dropped` report per-window losses/skips.
   Data frames addressed to/from the probe's own STA MAC are excluded to avoid
   feeding its telemetry transport back into capture.
2. Firmware publishes samples on `edge/telemetry/radio` (QoS 0, no retention) and
   prints `ESP32_RADIO:` lines. The USB bridge forwards these at QoS 1 with no
   retention. Device/boot/sequence deduplication removes the two transport copies.
   MQTT acknowledgments do not guarantee persistence; transport outages can lose
   samples. The four-slot queue is not an outage journal.
3. A host decoder validates size, types, identifiers, lengths and radio metadata,
   then streams LINKTYPE_IEEE802_11 PCAP bytes to a persistent TShark subprocess.
   It reuses the host's canonical feature parser, field order, raw categories and
   content extraction. PCAP bytes are piped, not saved as a second raw capture.
   Intake holds at most 128 samples, each dissector at most 64 pending frames;
   up to four device/boot streams run concurrently. Stalls fail after five seconds.
   Dissector state resets after 2048 frames to bound flow/reassembly history.
4. TShark rows on `edge/telemetry/traffic` feed the lake independently of the
   separately forwarded device inference and native-profile rows.
   Rows have `probe_type=esp32`, `capture_backend=esp32_tshark`, stable source packet
   IDs and `data_provenance=esp32-radio`. Dissector packet timing follows elapsed
   ESP32 uptime, anchored to host receipt of the segment's first sample, with
   wrap-safe increments; late reordered samples are dropped. Absolute capture
   timestamps are estimates (`timestamp_kind=estimated_capture_epoch_ms`), not
   synchronized UTC measurements. Original uptime (`source_timestamp`) and host
   receipt time (`received_at_ms`) remain separate. Source channel/RSSI are retained.
5. On-device inference uses its explicit native packet profile; the host does not
   re-run the wider packet model in ESP32 mode.
   Protected frames, fragments, frames without a decoded network protocol and
   truncated frames cannot become an all-zero Normal prediction: missing canonical
   fields are null and inference is unavailable. Window telemetry is never converted
   into packet features. Current radio rows are explicitly excluded from supervised
   training pending a radio-specific provenance/measurement audit.

Window messages still go to `edge/telemetry/traffic` for raw lake collection and
also `edge/telemetry/window` for dashboard rates/health. New windows identify
`radio_capture_version=1`; they do not overwrite packet inference. The lake stores
source `sniffer_mode` instead of overwriting it with the launcher's default.

## Measurement and model limits

ESP32 promiscuous mode observes frames on the current channel. Joining a WPA AP
does not provide decrypted third-party packet payloads to this path. No decryption
keys or fabricated TCP/HTTP/MQTT data are supplied. Protected payloads are unknown,
not protocol-absent zeros. A 2048-byte snapshot can truncate larger frames.

Plaintext dissection uses the host's protocol-absent sentinels, but sample gaps,
radio retries, out-of-order transport delivery, channel hopping and dissector resets
affect stream IDs, relative sequence fields and reassembly. Compatibility of column
names does not establish measurement parity, benchmark accuracy or deployment
validity. Available host scores are uncalibrated classifier outputs on observed
packet samples. No 15-class coverage or accuracy on radio traffic is claimed.

On-chip inference uses the separately trained ten-feature packet profile described
in [ESP32 Edge AI](ESP32_EDGE_AI.md). The existing 56-feature host model cannot
consume radio windows. Native extraction and Python–C parity are implemented;
the new model's alert performance is experimental and hardware validation remains
outstanding. Runtime does not train or replace model artifacts.

The dashboard uses the existing class probability bars for valid **device**
inference on ESP32 packets. Incompatible/insufficient data displays N/A; an anomaly
score is not a class probability. Serial output distinguishes radio/transport health
from inference. Local LED/buzzer alerts follow the on-device packet result before
transport and expire on stale/unavailable data.

Radio captures may contain private addresses, application payloads and SSIDs. They
follow the existing local lake retention and explicitly enabled remote-sync settings.

## Validation

`python -m unittest discover -s tests -p test_esp32_radio.py -v` exercises synthetic
frames, malformed bounds, encrypted/fragmented feature gating, MQTT-copy identity
deduplication, temporary Parquet persistence and native TShark pipe decoding.
It does not capture live traffic, change models, flash a board, or measure hardware
RAM, flash or latency. Compile firmware for the intended board/toolchain separately.

Protocol references: [ESP-IDF Wi-Fi API](https://docs.espressif.com/projects/esp-idf/en/v5.2/esp32/api-reference/network/esp_wifi.html)
and [TShark command reference](https://www.wireshark.org/docs/man-pages/tshark.html).
