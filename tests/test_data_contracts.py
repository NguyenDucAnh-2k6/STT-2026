"""Offline regression checks; no hardware, captures, or existing models modified."""
import io
import json
import os
import tempfile
import socket
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from broker.manager import build_runtime_config, check_mqtt_ready
from data_lake.collector import DataLakeCollector
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import select_training_records
from launcher.network import sync_env_to_firmware
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.inference_service import AnomalyInferenceEngine
from ml_engine.preprocessing import EdgeTrafficPreprocessor, load_and_preprocess_dataset, load_raw_dataset
from ml_engine.preprocessing.modules.base import numeric_series, normalize_categorical_value
from firmware.host_probe.tshark_engine import select_best_interfaces


def packet() -> dict:
    return {**dict.fromkeys(EDGE_IIOTSET_FEATURES, 0), "device_id": "test-probe",
            "timestamp": 1_800_000_000_000, "schema_version": 2, "packet_id": "test-packet-1",
            "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1",
            "capture_backend": "tshark", "missing_features": [],
            "label_verified": True, "label_source": "controlled_flow",
            "ground_truth_scenario": "Normal"}


class DataContractsTests(unittest.TestCase):
    def test_categories_encode_once(self) -> None:
        rows = [packet() for _ in range(4)]
        for row, method in zip(rows, ["GET", "POST", "GET", "POST"]):
            row.update({"http.request.method": method, "mqtt.topic": "sensors/test",
                        "tcp.payload": "100c00044d515454", "tcp.options": "020405b4"})
        frame = pd.DataFrame(rows)[EDGE_IIOTSET_FEATURES]
        processor = EdgeTrafficPreprocessor().fit(frame, pd.Series(["Normal"] * 4))
        for row in rows:
            np.testing.assert_allclose(processor.transform(processor.extract_features(row)),
                                       processor.transform(pd.DataFrame([row])[EDGE_IIOTSET_FEATURES]))
        self.assertGreater(len(processor.sub_preprocessors["tcp"]._cat_maps["tcp.payload"]), 1)

    def test_windows_do_not_fabricate_packet_features(self) -> None:
        processor = EdgeTrafficPreprocessor()
        raw = processor.extract_features({"packet_rate": 20, "byte_rate": 400,
                                          "syn_ratio": .8, "udp_ratio": .5})
        self.assertEqual(len(raw), 1)
        self.assertEqual(len(raw.columns), 0)

    def test_hex_scalar_and_invalid_numeric(self) -> None:
        parsed = numeric_series(pd.Series(["0x0010", "123", "host.local", float("inf")]))
        self.assertEqual(parsed.iloc[0], 16)
        self.assertTrue(parsed.iloc[2:].isna().all())
        broken = packet()
        broken["tcp.srcport"] = "host.local"
        accepted, report = select_training_records(pd.DataFrame([broken]))
        self.assertTrue(accepted.empty)
        self.assertEqual(report["reasons"]["malformed_numeric_features"], 1)
        self.assertEqual(normalize_categorical_value("00012345678901234567890"), "00012345678901234567890")

    def test_eligibility_rejects_windows_unknown_and_duplicates(self) -> None:
        good, window, unverified = packet(), packet(), packet()
        window.update(record_kind="window", feature_semantics="window-v1")
        unverified.update(ground_truth_scenario="Unknown", label_source="unattributed")
        accepted, report = select_training_records(pd.DataFrame([good, good, window, unverified]))
        self.assertEqual(len(accepted), 1)
        self.assertEqual(report["reasons"]["duplicate_identity"], 1)
        self.assertEqual(report["rejected"], 3)

    def test_automatic_attack_label_requires_no_verified_flag(self) -> None:
        row = packet()
        row.pop("label_verified")
        row.update(ground_truth_scenario="Port_Scanning", label_method="automatic_flow")
        accepted, _ = select_training_records(pd.DataFrame([row]))
        self.assertEqual(len(accepted), 1)
        row["label_verified"] = False  # Legacy flag is ignored, not silently made true.
        self.assertEqual(len(select_training_records(pd.DataFrame([row]))[0]), 1)
        row["label_source"] = "ui_scenario"
        self.assertEqual(len(select_training_records(pd.DataFrame([row]))[0]), 0)

    def test_legacy_lake_is_ineligible(self) -> None:
        accepted, _ = select_training_records(pd.DataFrame([{"packet_rate": 3, "ground_truth_scenario": "Normal"}]))
        self.assertTrue(accepted.empty)

    def test_split_before_scaler_fit(self) -> None:
        rows = [packet() for _ in range(40)]
        for index, row in enumerate(rows):
            row["tcp.len"] = index * index
            row["Attack_type"] = "Normal" if index % 2 == 0 else "DDoS_TCP"
        frame = pd.DataFrame(rows)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "benchmark.csv"
            frame.to_csv(path, index=False)
            with redirect_stdout(io.StringIO()):
                _, _, _, _, processor = load_and_preprocess_dataset(str(path), test_size=.25)
            raw_train, _, _, _ = train_test_split(frame, frame.Attack_type, test_size=.25,
                                                stratify=frame.Attack_type, random_state=42)
            column = processor.feature_names.index("tcp.len")
            self.assertAlmostEqual(processor.scaler.mean_[column], raw_train["tcp.len"].mean())
            self.assertNotEqual(processor.scaler.mean_[column], frame["tcp.len"].mean())

    def test_missing_benchmark_fails(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_raw_dataset("does-not-exist.csv")

    def test_bad_benchmark_is_not_silently_imputed(self) -> None:
        row = packet()
        row.update({"tcp.srcport": "host.local", "Attack_type": "Normal"})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.csv"
            pd.DataFrame([row]).to_csv(path, index=False)
            with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "Malformed benchmark"):
                load_raw_dataset(str(path))
            row["tcp.srcport"] = 1234
            pd.DataFrame([packet() | {"Attack_type": "Normal", "tcp.srcport": "host.local"}, row]).to_csv(path, index=False)
            with redirect_stdout(io.StringIO()):
                features, labels = load_raw_dataset(str(path), invalid_rows="drop")
            self.assertEqual(len(features), 1)
            self.assertEqual(features.attrs["data_quality"]["malformed_rows_removed"], 1)

    def test_training_reports_unavailable_metrics_and_keeps_zero_f1(self) -> None:
        from ml_engine.train import run_training_pipeline
        rows = [packet() for _ in range(96)]
        for index, row in enumerate(rows):
            row.update({"tcp.len": index, "Attack_type": "Normal" if index % 2 == 0 else "DDoS_TCP"})
        with tempfile.TemporaryDirectory() as folder:
            dataset = Path(folder) / "benchmark.csv"
            pd.DataFrame(rows).to_csv(dataset, index=False)
            output = Path(folder) / "models"
            original_fit = EdgeTrafficPreprocessor.fit
            with patch("ml_engine.train.export_model_to_c_header"), \
                 patch("ml_engine.algorithms.feature_importance.plot_and_save_feature_importance", return_value=None), \
                 patch("ml_engine.train.roc_auc_score", side_effect=ValueError("test evaluation unavailable")), \
                 patch.object(EdgeTrafficPreprocessor, "fit", autospec=True, side_effect=original_fit) as fitting, \
                 patch("ml_engine.train.f1_score", return_value=0.0), redirect_stdout(io.StringIO()):
                run_training_pipeline(dataset_path=str(dataset), output_dir=str(output),
                                      data_source="benchmark", sample_ratio=1, test_size=.25, cv=2)
            self.assertEqual([len(call.args[1]) for call in fitting.call_args_list], [72, 36, 36])
            metadata = json.loads((output / "model_metadata.json").read_text())
            self.assertEqual(metadata["classifier_macro_f1"], 0.0)
            self.assertIsNone(metadata["anomaly_test_roc_auc"])
            self.assertIsNone(metadata["anomaly_test_f1"])
            self.assertIn("unavailable", metadata["anomaly_evaluation_error"])
            self.assertEqual(metadata["preprocessing_version"], 2)
            self.assertEqual(metadata["test_samples"], 24)
            with redirect_stdout(io.StringIO()):
                engine = AnomalyInferenceEngine(models_dir=str(output))
                prediction = engine.predict(rows[0])
            self.assertEqual(prediction["inference_status"], "ok")

    def test_unsafe_time_series_path_is_blocked(self) -> None:
        from ml_engine.train import run_training_pipeline
        with tempfile.TemporaryDirectory() as folder, patch("ml_engine.train.load_raw_dataset") as loader:
            with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "Time-series training is disabled"):
                run_training_pipeline(output_dir=folder, use_timeseries=True)
            loader.assert_not_called()

    def test_unavailable_prediction_does_not_drive_defense(self) -> None:
        from digital_twin.closed_loop_service import ClosedLoopDefenseService
        from digital_twin.live_service import LiveDigitalTwinDaemon
        unavailable = {"inference_status": "unavailable", "anomaly_score": None}
        closed_loop = object.__new__(ClosedLoopDefenseService)
        live_twin = object.__new__(LiveDigitalTwinDaemon)
        # No controllers are initialized: any attempt at a defense step would fail.
        closed_loop._process_threat_detection(unavailable)
        live_twin._handle_rl_defense_step(unavailable)

    def test_inference_failure_is_unknown(self) -> None:
        engine = object.__new__(AnomalyInferenceEngine)
        engine.metadata = {"preprocessing_version": 2}
        engine.preprocessor = EdgeTrafficPreprocessor()
        engine.classifier = MagicMock()
        engine.anomaly_detector = MagicMock()
        engine.anomaly_threshold = .55
        with redirect_stdout(io.StringIO()):
            result = engine.predict({"device_id": "test", "record_kind": "window"})
        self.assertEqual(result["inference_status"], "unavailable")
        self.assertEqual(result["threat_type"], "Unknown")
        self.assertIsNone(result["anomaly_score"])
        self.assertIsNone(result["is_anomaly"])
        engine.classifier.predict_proba.assert_not_called()

    def test_manual_wifi_config_and_escaping(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "firmware/esp32_probe").mkdir(parents=True)
            config = {"WIFI_SSID": 'Test"SSID', "WIFI_PASSWORD": 'test\\password',
                      "MQTT_BROKER_HOST": "192.0.2.1", "MQTT_BROKER_PORT": "1884"}
            with patch.dict(os.environ, config, clear=True), patch("launcher.network.auto_detect_wifi_credentials") as detect:
                with redirect_stdout(io.StringIO()):
                    sync_env_to_firmware(folder)
                detect.assert_not_called()
            content = (Path(folder) / "firmware/esp32_probe/credentials.h").read_text()
            self.assertIn('#define WIFI_SSID "Test\\"SSID"', content)
            self.assertIn("#define MQTT_BROKER_PORT 1884", content)
            self.assertFalse((Path(folder) / ".env").exists())

    def test_runtime_broker_config_port_and_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "broker").mkdir()
            (Path(folder) / "broker/mosquitto.conf").write_text("listener 1883 0.0.0.0\npersistence_location ./broker/data/\n")
            config = Path(build_runtime_config(folder, 1884)).read_text()
            self.assertIn("listener 1884 0.0.0.0", config)
            self.assertIn(str(Path(folder) / "broker/data").replace("\\", "/"), config)

    def test_tcp_listener_is_not_automatically_mqtt(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            def reply() -> None:
                with listener.accept()[0] as connection:
                    connection.recv(256)
                    connection.sendall(b"HTTP")
            worker = threading.Thread(target=reply)
            worker.start()
            self.assertFalse(check_mqtt_ready(listener.getsockname()[1]))
            worker.join(timeout=2)

    def test_host_interface_selection(self) -> None:
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "2"}):
            self.assertEqual(select_best_interfaces([{"index": "2", "device": "test", "name": "Ethernet"}]), ["test"])
            with self.assertRaises(ValueError):
                select_best_interfaces([])

    def test_collector_ignores_scenario_as_label_and_deduplicates(self) -> None:
        lake = MagicMock()
        collector = DataLakeCollector(lake_manager=lake)
        collector.current_scenario = "DDoS_TCP"
        collector.is_attack_active = True
        payload = {"device_id": "test", "timestamp": 42, "boot_id": 1, "sequence": 1}
        msg = SimpleNamespace(topic="edge/telemetry/traffic", payload=json.dumps(payload).encode())
        collector._on_message(None, None, msg)
        collector._on_message(None, None, msg)
        self.assertEqual(lake.record_telemetry.call_count, 1)
        self.assertEqual(lake.record_telemetry.call_args.kwargs["ground_truth"], "Unknown")

    def test_lake_preserves_categories_and_unavailable_scores(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            lake = DataLakeManager(folder)
            with redirect_stdout(io.StringIO()):
                lake.start_session("host", "test")
                row = packet()
                row.update({"probe_type": "host", "http.request.method": "GET"})
                lake.record_telemetry(row, prediction={"inference_status": "unavailable", "anomaly_score": None})
                lake.close_session()
            files = list((Path(folder) / "raw").rglob("*.parquet"))
            frame = pd.read_parquet(files[0])
            self.assertEqual(frame["http.request.method"].iloc[0], "GET")
            self.assertEqual(frame["probe_type"].iloc[0], "host")
            self.assertEqual(frame["ground_truth_scenario"].iloc[0], "Unknown")
            self.assertTrue(frame.anomaly_score.isna().all())


if __name__ == "__main__":
    unittest.main()
