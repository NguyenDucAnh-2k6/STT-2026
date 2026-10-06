#!/usr/bin/env python3
"""
Edge AI Network Security System - Runtime System Launcher
==========================================================
Chỉ chịu trách nhiệm KHỞI ĐỘNG VẬN HÀNH hệ thống thời gian thực (Inference Only):
1. Khởi động Embedded Python MQTT Broker (nếu chưa có Mosquitto cài sẵn).
2. Kiểm tra Artifacts mô hình Machine Learning đã huấn luyện (scaler, classifier, detector, metadata).
3. Khởi động ML Real-time Inference Engine (kết nối MQTT, phát hiện bất thường & phân loại cuộc tấn công).
4. Khởi động Web Dashboard Server (FastAPI backend + Static Modern Glassmorphism UI + WebSocket).
5. Khởi động Telemetry Network Probe:
   - 'host': Host PC Live Network Sniffer (mặc định - bắt luồng mạng thật của máy tính).
   - 'esp32': Chế độ chờ dữ liệu từ thiết bị phần cứng ESP32 vật lý qua Wi-Fi/MQTT.
6. (Tùy chọn) Bắn gói tin độc hại mạng thật qua cờ `--attack-sim`:
   - Bắn gói tin thật (Port Scan, UDP Flood, TCP SYN Flood, Vuln Scan, Exfiltration) qua raw socket.
   - Điều khiển trực tiếp các kịch bản on-demand thông qua các nút bấm trên Web Dashboard.
"""

import os
import sys
import time
import argparse
import subprocess
import webbrowser
import signal
import multiprocessing
import threading
import shutil
from typing import Optional, Tuple, Any, List, Dict

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


from broker.embedded_broker import start_embedded_broker
from firmware.host_probe.host_sniffer import start_host_sniffer
from firmware.simulator.attack_traffic_generator import start_attack_traffic_generator, detect_target_ip
from data_lake import start_lake_collector, DataLakeCollector

# Tự động nạp biến môi trường từ file .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

processes = []
lake_collector: Optional[DataLakeCollector] = None
enable_remote_push: bool = False



from launcher import (
    detect_host_lan_ip,
    auto_detect_wifi_credentials,
    sync_env_to_firmware,
    check_port_in_use,
    udp_broker_beacon_worker,
    network_roaming_watcher_worker,
    serial_telemetry_bridge_worker,
    find_esp32_com_port,
    flash_esp32_cli,
)


def cleanup(sig=None, frame=None):
    """Dọn dẹp an toàn toàn bộ tiến trình con khi nhận tín hiệu kết thúc (Ctrl+C)."""
    print("\n\n" + "=" * 60)
    print("   DANG DUNG TOAN BO HE THONG EDGE AI SECURITY...")
    print("=" * 60)
    global lake_collector
    if lake_collector is not None:
        try:
            print("  [DataLake] Dang chot session va dong bo Parquet file vao kho du lieu...")
            lake_collector.stop()
        except Exception as e:
            print(f"  [DataLake] Canh bao khi dong lake collector: {e}")

    for p in processes:
        if isinstance(p, multiprocessing.Process):
            if p.is_alive():
                p.terminate()
                p.join(timeout=1.0)
        elif isinstance(p, subprocess.Popen):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    p.kill()

    global enable_remote_push
    if enable_remote_push:
        try:
            from data_lake.remote_storage import get_remote_storage_manager
            print("  [RemoteStorage] Dang dong bo toan bo phien lam viec len Cloudflare R2 / S3...")
            res = get_remote_storage_manager().sync_lake_to_remote()
            if res.get("success"):
                print(f"  [RemoteStorage] [OK] {res.get('message')}")
            else:
                print(f"  [RemoteStorage] {res.get('message')}")
        except Exception as e:
            print(f"  [RemoteStorage] Canh bao dong bo: {e}")

    print("   [OK] Tat ca tien trinh da dung an toan. Tam biet!\n")
    sys.exit(0)



def str_to_bool(val: Any) -> bool:
    """Chuyển đổi linh hoạt giá trị từ CLI thành boolean."""
    if isinstance(val, bool):
        return val
    s = str(val).lower().strip()
    if s in ("true", "1", "yes", "y", "t", "on"):
        return True
    elif s in ("false", "0", "no", "n", "f", "off"):
        return False
    raise argparse.ArgumentTypeError(f"Gia tri boolean khong hop le: '{val}' (chap nhan: true/false, 1/0)")


class SmartBooleanAction(argparse.Action):
    """
    Action thông minh cho các cờ boolean CLI:
    - Cho phép gõ trực tiếp cờ để BẬT: --attack-sim, --arduino-cli, --push-remote.
    - Cho phép gõ tiền tố --no-... để TẮT: --no-attack-sim, --no-arduino-cli.
    - Cho phép truyền tham số tường minh: --attack-sim true / false / 1 / 0.
    """
    def __init__(self, option_strings, dest, default=False, required=False, help=None, metavar="true/false"):
        opts = []
        for opt in option_strings:
            opts.append(opt)
            if opt.startswith("--") and not opt.startswith("--no-"):
                neg_opt = f"--no-{opt[2:]}"
                if neg_opt not in opts:
                    opts.append(neg_opt)
        super().__init__(
            option_strings=opts,
            dest=dest,
            nargs="?",
            const=True,
            default=default,
            required=required,
            help=help,
            metavar=metavar
        )

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string and option_string.startswith("--no-"):
            if values is None:
                setattr(namespace, self.dest, False)
            else:
                val_bool = str_to_bool(values)
                setattr(namespace, self.dest, not val_bool)
        elif values is None:
            setattr(namespace, self.dest, True)
        else:
            setattr(namespace, self.dest, str_to_bool(values))


def resolve_models_dir(root_dir: str, classifier: str, anomaly_model: str, custom_dir: Optional[str] = None) -> Tuple[str, str]:
    """
    Truy vết và tự động chuẩn bị thư mục chứa model artifacts cho BẤT KỲ tổ hợp dual model nào:
    1. Nếu người dùng chỉ định custom_dir: dùng custom_dir.
    2. Kiểm tra thư mục chuyên biệt: ml_engine/models/{classifier}_{anomaly_model}
    3. Nếu chưa có sẵn, tự động truy quét các folder artifacts con trong ml_engine/models/
       để tìm Classifier ({classifier}) và Anomaly Detector ({anomaly_model}) tương ứng,
       sau đó tự động tổng hợp tổ hợp dual model mới hoàn chỉnh kèm tinyml_model.h.
    """
    if custom_dir:
        return custom_dir, f"Thu muc chi dinh qua --models-dir ({custom_dir})"

    base_models = os.path.join(root_dir, "ml_engine", "models")
    clf_clean = classifier.lower().strip()
    ano_clean = anomaly_model.lower().strip()

    # Chuẩn hóa alias
    if clf_clean in ("dnn", "mlp", "deep_learning"):
        clf_clean = "pytorch_deep"
    if ano_clean == "autoencoder":
        ano_clean = "deep_autoencoder"

    target_combo_dir = os.path.join(base_models, f"{clf_clean}_{ano_clean}")

    # 1. Kiểm tra nếu thư mục tổ hợp đã tồn tại đầy đủ artifacts
    if os.path.exists(target_combo_dir):
        clf_p = os.path.join(target_combo_dir, "attack_classifier.joblib")
        iso_p = os.path.join(target_combo_dir, "isolation_forest.joblib")
        sc_p = os.path.join(target_combo_dir, "scaler.joblib")
        pr_p = os.path.join(target_combo_dir, "preprocessor.joblib")
        if os.path.exists(clf_p) and os.path.exists(iso_p) and (os.path.exists(sc_p) or os.path.exists(pr_p)):
            return target_combo_dir, f"Thu muc to hop chuyen biet ({clf_clean}_{ano_clean})"

    # 2. Quét các folder con để tìm từng model thành phần
    found_clf_dir = None
    found_ano_dir = None
    shared_prep_dir = None

    if os.path.exists(base_models):
        for entry in sorted(os.listdir(base_models)):
            subpath = os.path.join(base_models, entry)
            if not os.path.isdir(subpath):
                continue

            meta_file = os.path.join(subpath, "model_metadata.json")
            clf_file = os.path.join(subpath, "attack_classifier.joblib")
            ano_file = os.path.join(subpath, "isolation_forest.joblib")

            # Tìm classifier khớp
            if os.path.exists(clf_file) and not found_clf_dir:
                matched = False
                if os.path.exists(meta_file):
                    try:
                        import json
                        with open(meta_file, "r", encoding="utf-8") as f:
                            mdata = json.load(f)
                            m_clf = mdata.get("classifier_type", "").lower()
                            if m_clf in ("dnn", "mlp", "deep_learning"):
                                m_clf = "pytorch_deep"
                            if m_clf == clf_clean:
                                matched = True
                    except Exception:
                        pass
                if not matched and clf_clean in entry.lower():
                    matched = True
                if matched:
                    found_clf_dir = subpath

            # Tìm anomaly detector khớp
            if os.path.exists(ano_file) and not found_ano_dir:
                matched = False
                if os.path.exists(meta_file):
                    try:
                        import json
                        with open(meta_file, "r", encoding="utf-8") as f:
                            mdata = json.load(f)
                            m_ano = mdata.get("anomaly_detector_type", "").lower()
                            if m_ano == "autoencoder":
                                m_ano = "deep_autoencoder"
                            if m_ano == ano_clean:
                                matched = True
                    except Exception:
                        pass
                if not matched and ano_clean in entry.lower():
                    matched = True
                if matched:
                    found_ano_dir = subpath

            if (os.path.exists(os.path.join(subpath, "scaler.joblib")) or
                os.path.exists(os.path.join(subpath, "preprocessor.joblib"))) and not shared_prep_dir:
                shared_prep_dir = subpath

    # 3. Tự động tổng hợp tổ hợp dual model nếu tìm thấy cả 2 thành phần
    if found_clf_dir and found_ano_dir:
        os.makedirs(target_combo_dir, exist_ok=True)
        print(f"\n  [Dual Model Synthesis] Dang tong hop to hop moi '{clf_clean} + {ano_clean}'...")
        print(f"    * Nguon Classifier ({clf_clean})      : {os.path.basename(found_clf_dir)}")
        print(f"    * Nguon Anomaly Model ({ano_clean})   : {os.path.basename(found_ano_dir)}")

        # Copy classifier artifacts
        shutil.copy2(os.path.join(found_clf_dir, "attack_classifier.joblib"), os.path.join(target_combo_dir, "attack_classifier.joblib"))
        if os.path.exists(os.path.join(found_clf_dir, "classifier_dnn.tflite")):
            shutil.copy2(os.path.join(found_clf_dir, "classifier_dnn.tflite"), os.path.join(target_combo_dir, "classifier_dnn.tflite"))

        # Copy anomaly detector artifacts
        shutil.copy2(os.path.join(found_ano_dir, "isolation_forest.joblib"), os.path.join(target_combo_dir, "isolation_forest.joblib"))
        if os.path.exists(os.path.join(found_ano_dir, "anomaly_autoencoder.tflite")):
            shutil.copy2(os.path.join(found_ano_dir, "anomaly_autoencoder.tflite"), os.path.join(target_combo_dir, "anomaly_autoencoder.tflite"))

        # Copy scaler/preprocessor
        prep_src = shared_prep_dir or found_clf_dir or found_ano_dir
        if os.path.exists(os.path.join(prep_src, "scaler.joblib")):
            shutil.copy2(os.path.join(prep_src, "scaler.joblib"), os.path.join(target_combo_dir, "scaler.joblib"))
        if os.path.exists(os.path.join(prep_src, "preprocessor.joblib")):
            shutil.copy2(os.path.join(prep_src, "preprocessor.joblib"), os.path.join(target_combo_dir, "preprocessor.joblib"))

        # Tự động xuất C Header tinyml_model.h hoàn chỉnh cho tổ hợp này
        try:
            import joblib
            from ml_engine.exporter.tinyml_exporter import export_model_to_c_header
            clf_obj = joblib.load(os.path.join(target_combo_dir, "attack_classifier.joblib"))
            ano_obj = joblib.load(os.path.join(target_combo_dir, "isolation_forest.joblib"))
            prep_obj = joblib.load(os.path.join(target_combo_dir, "preprocessor.joblib")) if os.path.exists(os.path.join(target_combo_dir, "preprocessor.joblib")) else None
            h_path = os.path.join(target_combo_dir, "tinyml_model.h")
            export_model_to_c_header(clf_obj, ano_obj, h_path, preprocessor=prep_obj)
            print(f"    * Da tao C Header tinyml_model.h cho to hop: {h_path}")
        except Exception as e:
            print(f"    [Warning] Khong the tu dong tao tinyml_model.h cho to hop: {e}")

        # Tự động xuất model_metadata.json cho tổ hợp mới
        try:
            import json
            combo_meta = {
                "classifier_type": clf_clean,
                "anomaly_detector_type": ano_clean,
                "synthesized": True,
                "classifier_source": os.path.basename(found_clf_dir),
                "anomaly_source": os.path.basename(found_ano_dir),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            clf_meta_path = os.path.join(found_clf_dir, "model_metadata.json")
            if os.path.exists(clf_meta_path):
                with open(clf_meta_path, "r", encoding="utf-8") as f:
                    clf_m = json.load(f)
                    for k in ("features", "labels", "features_count", "labels_count", "classifier_accuracy", "classifier_macro_f1"):
                        if k in clf_m:
                            combo_meta[k] = clf_m[k]
            with open(os.path.join(target_combo_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
                json.dump(combo_meta, f, indent=2)
        except Exception:
            pass

        return target_combo_dir, f"To hop tu dong tong hop ({clf_clean} + {ano_clean})"

    # Fallback: Quét folder đầu tiên hợp lệ
    if os.path.exists(base_models):
        for entry in sorted(os.listdir(base_models)):
            subpath = os.path.join(base_models, entry)
            if os.path.isdir(subpath):
                clf_p = os.path.join(subpath, "attack_classifier.joblib")
                iso_p = os.path.join(subpath, "isolation_forest.joblib")
                if os.path.exists(clf_p) and os.path.exists(iso_p):
                    return subpath, f"Thu muc model fallback tu dong tim thay ({entry})"

    return target_combo_dir, f"Thu muc model ({clf_clean}_{ano_clean})"


def sync_tinyml_header_to_firmware(root_dir: str, models_dir: str, classifier: str, anomaly_model: str) -> bool:
    """
    Tự động sao chép và ghi đè C Header TinyML (tinyml_model.h) và các file .tflite (nếu có)
    từ thư mục models tương ứng sang firmware/esp32_probe/.
    """
    candidate_paths = [
        os.path.join(models_dir, "tinyml_model.h"),
        os.path.join(root_dir, "ml_engine", "models", f"{classifier.lower()}_{anomaly_model.lower()}", "tinyml_model.h"),
    ]
    base_models = os.path.join(root_dir, "ml_engine", "models")
    if os.path.exists(base_models):
        for entry in sorted(os.listdir(base_models)):
            candidate_paths.append(os.path.join(base_models, entry, "tinyml_model.h"))

    source_header = None
    for cp in candidate_paths:
        if os.path.exists(cp) and os.path.getsize(cp) > 500:
            source_header = cp
            break

    if not source_header:
        print("  [TinyML Sync] Canh bao: Khong tim thay tep tinyml_model.h hop le de dong bo!")
        return False

    firmware_dir = os.path.join(root_dir, "firmware", "esp32_probe")
    os.makedirs(firmware_dir, exist_ok=True)
    dest_header = os.path.join(firmware_dir, "tinyml_model.h")

    try:
        shutil.copy2(source_header, dest_header)
        sz = os.path.getsize(dest_header)
        print(f"  [TinyML Sync] Da tu dong dong bo & ghi de tinyml_model.h sang firmware ESP32 ({sz:,} bytes):")
        print(f"                Nguon : {source_header}")
        print(f"                Dich  : {dest_header}")

        # Đồng bộ thêm các file .tflite nếu có trong models_dir
        for tflite_name in ("classifier_dnn.tflite", "anomaly_autoencoder.tflite"):
            tf_src = os.path.join(models_dir, tflite_name)
            if os.path.exists(tf_src):
                tf_dest = os.path.join(firmware_dir, tflite_name)
                shutil.copy2(tf_src, tf_dest)
                print(f"                TFLite: {tflite_name} ({os.path.getsize(tf_dest):,} bytes) -> firmware")

        return True
    except Exception as e:
        print(f"  [TinyML Sync Warning] Khong the ghi de tinyml_model.h sang firmware: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Edge AI Real-time Anomaly Detection & Attack Classification Runtime",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.55,
        help="Nguong canh bao Anomaly Score tren toan he thong (mac dinh: 0.55)"
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=1883,
        help="Port cho MQTT Broker (mac dinh: 1883)"
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8000,
        help="Port cho Web Dashboard FastAPI (mac dinh: 8000)"
    )
    parser.add_argument(
        "--probe",
        default="host",
        choices=["host", "esp32", "sim"],
        help="Nguon du lieu Telemetry: 'host' (bat goi tin mang that tren PC), 'esp32' (cho du lieu tu phan cung ESP32 vat ly), 'sim' (gia lap telemetry)"
    )
    parser.add_argument(
        "--no-sim",
        dest="no_sim",
        action=SmartBooleanAction,
        default=False,
        help="Chay che do phan cung ESP32 vat ly (tuong duong --probe esp32)"
    )
    parser.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Cua so lay mau telemetry giay (mac dinh: 1.0s)"
    )
    parser.add_argument(
        "--no-browser",
        dest="no_browser",
        action=SmartBooleanAction,
        default=False,
        help="Khong tu dong mo trinh duyet Web Dashboard khi khoi dong (go --no-browser de tat mo browser)"
    )
    parser.add_argument(
        "--attack-sim",
        dest="attack_sim",
        action=SmartBooleanAction,
        default=False,
        help="Kich hoat bo ban goi tin doc hai mang that (Port Scan, UDP Flood, SYN Flood, Vuln Scan, Exfiltration) qua raw socket, dieu khien tu Dashboard (Go --attack-sim de BAT; hoac --no-attack-sim de TAT)"
    )
    parser.add_argument(
        "--attack-target",
        default=None,
        help="IP dich de ban goi tin doc hai khi dung --attack-sim (mac dinh: tu dong do tim Gateway / Broadcast / ESP32 IP)"
    )
    parser.add_argument(
        "--arduino-cli",
        "--arduino_cli",
        dest="arduino_cli",
        action=SmartBooleanAction,
        default=False,
        help="Tu dong bien dich va nap firmware sang ESP32 qua arduino-cli (Go --arduino-cli de BAT; hoac --no-arduino-cli de TAT)"
    )
    parser.add_argument(
        "--flash",
        dest="arduino_cli",
        action="store_true",
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--port",
        "--com-port",
        dest="com_port",
        default=None,
        help="Chi dinh cong Serial/COM cua ESP32 (mac dinh: tu dong do tim, vd: COM4 tren Windows, /dev/ttyUSB0 tren Linux)"
    )
    parser.add_argument(
        "--record-lake",
        dest="record_lake",
        action=SmartBooleanAction,
        default=True,
        help="Tu dong ghi luu toan bo telemetries vao Data Lakehouse Parquet/SQLite (Mac dinh: BAT; go --no-record-lake hoac --no-record de TAT)"
    )
    parser.add_argument(
        "--classifier",
        default="decision_tree",
        choices=[
            "decision_tree", "random_forest", "extra_trees", "xgboost", "xgb",
            "lightgbm", "lgb", "catboost", "gradient_boosting", "pytorch_deep", "dnn", "mlp", "deep_learning",
            "logistic_regression", "ensemble_voting"
        ],
        help=(
            "Loai Attack Classifier can nap (8 mo hinh phan loai chinh):\n"
            "  [Nhom Edge TinyML C Header / TFLite cho ESP32]:\n"
            "  * decision_tree      : Cây quyết định (C Header TinyML siêu nhẹ)\n"
            "  * random_forest      : Rừng cây ngẫu nhiên (C Header TinyML soft-voting)\n"
            "  * extra_trees        : Extra Trees Ensemble (C Header TinyML)\n"
            "  * pytorch_deep / dnn : Deep Neural Network (TFLite FlatBuffer C array cho ESP32)\n"
            "  * logistic_regression: Hồi quy Logistic tuyến tính (C Header Softmax)\n"
            "  [Nhom High-Performance Server GBDT]:\n"
            "  * xgboost / xgb      : XGBoost Gradient Boosting\n"
            "  * lightgbm / lgb     : LightGBM Histogram GBDT\n"
            "  * catboost           : CatBoost Classifier\n"
            "  * gradient_boosting  : Scikit-learn Gradient Boosting Baseline\n"
            "  * ensemble_voting    : Tổ hợp mềm Soft-Voting Ensemble (RF + ET + XGB)"
        )
    )
    parser.add_argument(
        "--anomaly-model", "--anomaly_model",
        default="isolation_forest",
        choices=[
            "isolation_forest", "deep_autoencoder", "autoencoder",
            "one_class_svm", "elliptic_envelope", "lof"
        ],
        help=(
            "Loai Anomaly Detector can nap (6 mo hinh phat hien bat thuong):\n"
            "  [Nhom Edge TinyML C Header / TFLite cho ESP32]:\n"
            "  * isolation_forest   : Cô lập rừng cây ngẫu nhiên (C Header TinyML)\n"
            "  * deep_autoencoder   : Deep Autoencoder (TFLite FlatBuffer C array cho ESP32)\n"
            "  * one_class_svm      : One-Class SVM RBF Kernel (C Header TinyML)\n"
            "  * elliptic_envelope  : Robust Gaussian Mahalanobis (C Header TinyML)\n"
            "  * lof                : Local Outlier Factor K-Nearest Density (C Header TinyML)"
        )
    )
    parser.add_argument(
        "--models-dir",
        default=None,
        help="Chi dinh truc tiep thu muc chua artifacts mo hinh (mac dinh: tu dong tim kiem hoac tong hop to hop)"
    )
    parser.add_argument(
        "--push-remote",
        dest="push_remote",
        action=SmartBooleanAction,
        default=False,
        help="Tu dong dong bo toan bo phan vung Parquet len Cloudflare R2 / S3 (Go --push-remote de BAT; hoac --no-push-remote de TAT)"
    )
    parser.add_argument(
        "--no-record",
        dest="record_lake",
        action="store_false",
        help="Tat che do ghi vao Data Lakehouse (tuong duong --no-record-lake)"
    )

    args = parser.parse_args()

    # Thiết lập trạng thái remote push toàn cục
    global enable_remote_push
    enable_remote_push = getattr(args, "push_remote", False) or (os.getenv("R2_AUTO_SYNC", "false").lower() in ("true", "1", "yes"))

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable

    # Xac dinh che do probe
    if args.no_sim:
        probe_mode = "esp32"
    elif args.probe == "sim":
        print("\n[Luu y] Che do 'sim' (so lieu ao) da duoc thay the bang bo ban goi tin mang that 100%.")
        print("        Tu dong chuyen sang: --probe host --attack-sim\n")
        probe_mode = "host"
        args.attack_sim = True
    else:
        probe_mode = args.probe

    print("=" * 70)
    print("   EDGE AI NETWORK ANOMALY DETECTION SYSTEM - RUNTIME LAUNCHER")
    print(f"   [Mode: INFERENCE ONLY] | [Probe: {probe_mode.upper()}]")
    print(f"   [Target Models: Classifier='{args.classifier}', Anomaly='{args.anomaly_model}']")
    if enable_remote_push:
        print("   [Cloud Sync: KICH HOAT (Tu dong push len Cloudflare R2 / S3)]")
    if args.attack_sim:
        print("   [Attack Simulator: KICH HOAT (Ban goi tin mang that, dieu khien tu Web UI)]")
    if args.arduino_cli:
        print("   [CLI Auto-Flash ESP32 (arduino-cli): KICH HOAT (Tu dong build & nap qua CLI)]")
    print("=" * 70)

    # Dong bo cau hinh credentials neu co thiet lap (tu dong lay SSID/Pass qua netsh ngam)
    sync_env_to_firmware(root_dir)

    # Tu dong xac dinh thu muc model va dong bo C Header TinyML sang firmware ESP32
    models_dir, models_source = resolve_models_dir(root_dir, args.classifier, args.anomaly_model, args.models_dir)
    sync_tinyml_header_to_firmware(root_dir, models_dir, args.classifier, args.anomaly_model)

    # 0. Neu co yeu cau nap firmware cho ESP32 qua CLI (arduino-cli)
    if args.arduino_cli:
        flash_ok = flash_esp32_cli(root_dir, com_port=args.com_port)
        if not flash_ok:
            print("  [Nhac nho] Ban van co the mo Arduino IDE de nap code bang tay neu muon.")

    # 1. Kiem tra va khoi dong MQTT Broker
    print(f"\n[1/5] Kiem tra MQTT Broker tai port {args.broker_port}...")
    if check_port_in_use(args.broker_port):
        print(f"  -> Da phat hien MQTT Broker dang hoat dong tai port {args.broker_port}.")
    else:
        print(f"  -> Chua co Broker. Dang khoi dong Embedded Python MQTT Broker tren port {args.broker_port}...")
        p_broker = multiprocessing.Process(
            target=start_embedded_broker,
            kwargs={"host": "0.0.0.0", "port": args.broker_port},
            daemon=True
        )
        p_broker.start()
        processes.append(p_broker)
        time.sleep(1.5)
        if check_port_in_use(args.broker_port):
            print(f"  -> Embedded MQTT Broker da san sang tren port {args.broker_port}!")
        else:
            print("  [Canh bao] Chua khoi dong duoc broker, he thong se tiep tuc...")

    # 1.1 Khoi dong Data Lakehouse Collector neu co bat
    global lake_collector
    if getattr(args, "record_lake", True):
        try:
            lake_collector = start_lake_collector(
                broker_host="127.0.0.1",
                broker_port=args.broker_port,
                buffer_size=50,
                flush_interval=5.0
            )
            print(f"  -> Data Lakehouse Collector: DA SAN SANG (Ghi Parquet vao data_lake/raw/ | Session: {lake_collector.session_id})")
        except Exception as e:
            print(f"  [DataLake] Canh bao: Khong the khoi dong Data Lake Collector: {e}")

    # 1.2 Khoi dong Periodic Cloud Sync neu bat --push-remote
    if enable_remote_push:
        try:
            from data_lake.remote_storage import get_remote_storage_manager
            r_mgr = get_remote_storage_manager()
            ok_r, msg_r = r_mgr.is_configured_and_available()
            if ok_r:
                print(f"  -> Remote Storage ({r_mgr._provider_name}): DA SAN SANG ({r_mgr.endpoint} | Bucket: {r_mgr.bucket_name})")
                def _periodic_sync_worker():
                    while True:
                        time.sleep(300)
                        try:
                            r_mgr.sync_lake_to_remote()
                        except Exception:
                            pass
                t_r = threading.Thread(target=_periodic_sync_worker, daemon=True)
                t_r.start()
            else:
                print(f"  [RemoteStorage] Canh bao: {msg_r}")
        except Exception as e:
            print(f"  [RemoteStorage] Canh bao khoi tao: {e}")

    # 2. Kiem tra Model Artifacts theo co --classifier & --anomaly-model
    models_dir, models_source = resolve_models_dir(root_dir, args.classifier, args.anomaly_model, args.models_dir)
    print("\n[2/5] Kiem tra Artifacts mo hinh Machine Learning...")
    print(f"  * Thu muc nguon : {models_dir}")
    print(f"  * Chi tiet nguon: {models_source}")


    model_path = os.path.join(models_dir, "attack_classifier.joblib")
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    meta_path = os.path.join(models_dir, "model_metadata.json")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    prep_path = os.path.join(models_dir, "preprocessor.joblib")

    has_scaler = os.path.exists(scaler_path) or os.path.exists(prep_path)
    if not (os.path.exists(model_path) and os.path.exists(iso_path) and has_scaler):
        print("\n" + "=" * 76)
        print("  [NHAC NHO QUAN TRONG] CHUA TIM THAY ARTIFACTS MO HINH MACHINE LEARNING!")
        print("=" * 76)
        print(f"  He thong da tim kiem tai: {models_dir}")
        print("  nhung khong co du cac tep weights can thiet.")
        print("\n  Vui long chay quy trinh huan luyen offline cho cap model nay truoc:")
        print(f"      python ml_engine/train.py --classifier {args.classifier} --anomaly-model {args.anomaly_model}")
        print("\n  Hoac toi uu hoa sieu tham so (HPO) voi Optuna:")
        print(f"      python ml_engine/train.py --classifier {args.classifier} --optuna")
        print("\n  Sau khi huan luyen thanh cong va xuat artifacts, hay chay lai:")
        print(f"      python run_system.py --classifier {args.classifier} --anomaly-model {args.anomaly_model}")
        print("=" * 76 + "\n")
        cleanup()
        sys.exit(1)

    clf_name = args.classifier
    det_name = args.anomaly_model
    import json
    try:
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            clf_name = meta.get("classifier_type", args.classifier)
            det_name = meta.get("anomaly_detector_type", args.anomaly_model)
            feat_cnt = meta.get("features_count", len(meta.get("features", [])))
            lbl_cnt = meta.get("labels_count", len(meta.get("labels", [])))
            acc = meta.get("classifier_accuracy", 0.0)
            macro_f1 = meta.get("classifier_macro_f1", 0.0)
            print(f"  -> Da load thanh cong Artifacts da huan luyen:")
            print(f"     * Classifier Model       : {clf_name} (Accuracy: {acc*100:.2f}%, Macro F1: {macro_f1*100:.2f}%)")
            print(f"     * Anomaly Detector       : {det_name}")
            print(f"     * Schema Features        : {feat_cnt} dac trung (Edge-IIoTset)")
            print(f"     * Nhan phan loai tan cong: {lbl_cnt} lop")
        else:
            print(f"  -> Da tim thay artifacts model tai {models_dir} (Classifier: {clf_name}, Detector: {det_name})")
    except Exception as e:
        print(f"  -> Da tim thay artifacts model tai {models_dir} (Chi tiet meta: {e})")

    # 3. Khoi dong ML Inference Service voi dung MODELS_DIR
    print("\n[3/5] Khoi dong ML Real-time Inference Engine...")
    inference_script = os.path.join(root_dir, "ml_engine", "inference_service.py")
    env_inf = os.environ.copy()
    env_inf["MQTT_HOST"] = "127.0.0.1"
    env_inf["MQTT_BROKER_HOST"] = "127.0.0.1"
    env_inf["MQTT_PORT"] = str(args.broker_port)
    env_inf["ANOMALY_THRESHOLD"] = str(args.threshold)
    env_inf["MODELS_DIR"] = models_dir
    p_inference = subprocess.Popen([python_exe, inference_script], env=env_inf)
    processes.append(p_inference)
    time.sleep(1.0)


    # 4. Khoi dong Dashboard Backend (FastAPI)
    print(f"\n[4/5] Khoi dong Web Dashboard Server tren port {args.dashboard_port}...")
    dashboard_script = os.path.join(root_dir, "dashboard", "backend", "app.py")
    env = os.environ.copy()
    env["PORT"] = str(args.dashboard_port)
    env["MQTT_HOST"] = "127.0.0.1"
    env["MQTT_BROKER_HOST"] = "127.0.0.1"
    env["MQTT_PORT"] = str(args.broker_port)
    p_dashboard = subprocess.Popen([python_exe, dashboard_script], env=env)
    processes.append(p_dashboard)
    time.sleep(2.0)

    # 5. Khoi dong Telemetry Probe (Host Sniffer hoac cho ESP32 vat ly)
    if probe_mode == "host":
        print("\n[5/5] Khoi dong Host PC Live Network Sniffer (Bat luu luong mang that cua may tinh)...")
        p_sniffer = multiprocessing.Process(
            target=start_host_sniffer,
            kwargs={
                "broker_host": "127.0.0.1",
                "broker_port": args.broker_port,
                "window_sec": args.window
            },
            daemon=True
        )
        p_sniffer.start()
        processes.append(p_sniffer)
    else:
        print("\n[5/5] Che do ESP32 vat ly: He thong dang cho du lieu tu phan cung ESP32 qua WiFi/MQTT & USB Serial...")
        print("  -> Bo mach ESP32 Promiscuous bat luu luong Wi-Fi over-the-air va day ve qua MQTT & USB Serial.")

        # 1. Kích hoạt luồng UDP Auto-Discovery Beacon giúp ESP32 tự nhận diện IP Broker khi chuyển mạng
        t_beacon = threading.Thread(target=udp_broker_beacon_worker, args=(args.broker_port,), daemon=True)
        t_beacon.start()

        # 2. Kích hoạt luồng Network Roaming Watcher tự động giám sát thay đổi mạng máy tính
        t_roaming = threading.Thread(target=network_roaming_watcher_worker, args=(root_dir,), daemon=True)
        t_roaming.start()

        # 3. Kích hoạt luồng USB Serial Telemetry Bridge dự phòng nếu có cổng COM kết nối
        esp_port = args.com_port or find_esp32_com_port()
        if esp_port:
            t_bridge = threading.Thread(target=serial_telemetry_bridge_worker, args=(esp_port, args.broker_port), daemon=True)
            t_bridge.start()

    # 6. Khoi dong Attack Traffic Generator neu nguoi dung bat co --attack-sim
    if args.attack_sim:
        target_ip = args.attack_target or detect_target_ip()
        print(f"\n[AttackSim] >>> KICH HOAT BO BAN GOI TIN DOC HAI MANG THAT (RAW SOCKET) <<<")
        print(f"  * Target IP: {target_ip}")
        print(f"  * Dieu khien: Nut bam tren Web Dashboard se phat dong tan cong that toi {target_ip}!")
        print(f"  * Sniffer ({probe_mode.upper()}) se thuc su bat duoc cac goi tin nay de ML phan loai!")
        p_attack_gen = multiprocessing.Process(
            target=start_attack_traffic_generator,
            kwargs={
                "target_ip": target_ip,
                "broker_host": "127.0.0.1",
                "broker_port": args.broker_port,
                "cycle_interval": 12.0
            },
            daemon=True
        )
        p_attack_gen.start()
        processes.append(p_attack_gen)

    # Thong bao va mo trinh duyet
    dashboard_url = f"http://localhost:{args.dashboard_port}"
    probe_desc = "Live PC Traffic Sniffer" if probe_mode == "host" else "Physical ESP32 Wi-Fi Hardware"
    print("\n" + "=" * 70)
    print(" [OK] HE THONG DA HOAT DONG TOAN DIEN!")
    print(f"  -> Web Dashboard        : {dashboard_url}")
    print(f"  -> Luong Telemetry      : {probe_desc} -> MQTT:{args.broker_port} -> ML Engine -> WebSocket")
    print(f"  -> Model Classifier     : {clf_name}")
    print(f"  -> Model Anomaly        : {det_name}")
    print(f"  -> Probe Source         : {probe_mode.upper()} ({probe_desc})")
    print(f"  -> Data Lakehouse       : {'BAT (Luu data_lake/raw/ partitioned theo ngay)' if getattr(args, 'record_lake', True) else 'TAT'}")
    print(f"  -> Attack Simulation    : {'BAT (Dieu khien on-demand tu Web UI)' if args.attack_sim else 'TAT'}")
    print(f"  -> Nguong canh bao      : {args.threshold}")
    print("  -> Nhan Ctrl + C de dung toan bo he thong.")
    print("=" * 70 + "\n")

    if not args.no_browser:
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    # Giữ tiến trình launcher sống
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
