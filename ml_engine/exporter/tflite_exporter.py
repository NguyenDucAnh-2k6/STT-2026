"""
TensorFlow Lite (TFLite) FlatBuffer Exporter for Embedded Deep Learning (ESP32)
================================================================================
Chỉ dẫn module:
- Module này là Handler chính quản lý việc xuất TẤT CẢ các mô hình Deep Learning (DNN, LSTM, Autoencoder)
  sang định dạng chuẩn TensorFlow Lite (.tflite) và mảng C FlatBuffer (tinyml_tflite_array.h) cho vi điều khiển ESP32.
- Nhập toàn bộ logic trích xuất trọng số toán học và đồ thị từ deep_learning_exporter.py,
  tuyệt đối không bịa đặt trọng số hay dùng logic từ đầu thiếu đồng bộ.
- 100% Zero-Heuristic: Mọi trọng số đều được trích xuất 1:1 từ computation graph PyTorch đã huấn luyện.
"""

import os
import sys
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from .common import (
    _format_float,
    _format_float_1d_array,
    _format_float_2d_array,
    format_bytes_as_c_array
)
from .deep_learning_exporter import (
    is_deep_learning_model,
    is_lstm_model,
    extract_folded_pytorch_dnn_weights,
    extract_pytorch_lstm_weights,
    extract_pytorch_autoencoder_weights,
    build_keras_dnn_model,
    build_keras_lstm_model,
    build_keras_autoencoder_model
)


def convert_keras_to_tflite(model: Any) -> bytes:
    """Chuyển đổi một Keras Model sang FlatBuffer byte array của TensorFlow Lite (.tflite)."""
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow chưa được cài đặt trong môi trường để xuất TFLite.")
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    return converter.convert()


def convert_pytorch_classifier_to_tflite(
    classifier_model: Any,
    in_features: int = 56,
    num_classes: int = 15,
    window_size: int = 10,
    output_path: Optional[str] = None
) -> bytes:
    """
    Chuyển đổi PyTorch Classifier (EdgeDeepNet hoặc EdgeLSTMNet) sang TFLite FlatBuffer bytes.
    Sử dụng trọng số thực tế đã huấn luyện.
    """
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow chưa được cài đặt trong môi trường để xuất TFLite.")

    if is_lstm_model(classifier_model):
        lstm_data = extract_pytorch_lstm_weights(classifier_model)
        in_feat = lstm_data.get("in_features", in_features)
        n_classes = lstm_data.get("num_classes", num_classes)
        keras_model = build_keras_lstm_model(
            lstm_data=lstm_data,
            in_features=in_feat,
            num_classes=n_classes,
            window_size=window_size
        )
    else:
        folded_weights, extracted_in_feat, extracted_num_classes = extract_folded_pytorch_dnn_weights(classifier_model)
        in_feat = extracted_in_feat or in_features
        n_classes = extracted_num_classes or num_classes
        keras_model = build_keras_dnn_model(
            folded_weights=folded_weights,
            in_features=in_feat,
            num_classes=n_classes
        )

    tflite_bytes = convert_keras_to_tflite(keras_model)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(tflite_bytes)
        print(f"[TFLiteExporter] Da luu Classifier TFLite: {output_path} ({len(tflite_bytes):,} bytes)")

    return tflite_bytes


def convert_pytorch_autoencoder_to_tflite(
    anomaly_model: Any,
    in_features: int = 56,
    latent_dim: int = 8,
    output_path: Optional[str] = None
) -> bytes:
    """
    Chuyển đổi PyTorch AutoencoderNet sang TFLite FlatBuffer bytes.
    Sử dụng trọng số thực tế đã huấn luyện, không tạo model ngẫu nhiên.
    """
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow chưa được cài đặt trong môi trường để xuất TFLite.")

    weights, in_feat, lat_dim, _, _, _ = extract_pytorch_autoencoder_weights(anomaly_model)
    in_feat = in_feat or in_features
    lat_dim = lat_dim or latent_dim

    keras_ae = build_keras_autoencoder_model(
        weights=weights,
        in_features=in_feat,
        latent_dim=lat_dim
    )

    tflite_bytes = convert_keras_to_tflite(keras_ae)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(tflite_bytes)
        print(f"[TFLiteExporter] Da luu Autoencoder TFLite: {output_path} ({len(tflite_bytes):,} bytes)")

    return tflite_bytes


def generate_tflite_array_header(
    classifier_bytes: Optional[bytes],
    anomaly_bytes: Optional[bytes],
    preprocessor: Optional[Any],
    label_names: Optional[List[str]],
    anomaly_threshold: float = 0.50
) -> str:
    """Sinh tệp header C (tinyml_tflite_array.h) chứa mảng FlatBuffer nhị phân nhúng trực tiếp cho ESP32."""
    c_lines = [
        "// =====================================================================",
        "// TENSORFLOW LITE FLATBUFFER EMBEDDED C ARRAYS (ESP32 PROBE)",
        "// Sinh tự động từ trọng số thực tế của PyTorch Deep Learning Models",
        "// 100% Zero-Heuristic: Trọng số computation graph 1:1",
        "// =====================================================================",
        "#ifndef TINYML_TFLITE_ARRAY_H",
        "#define TINYML_TFLITE_ARRAY_H",
        "",
        "#include <stdint.h>",
        "#include <stdbool.h>",
        ""
    ]

    # Preprocessor scaler means & stds
    feat_count = 56
    means = np.zeros(feat_count, dtype=np.float32)
    scales = np.ones(feat_count, dtype=np.float32)

    if preprocessor is not None:
        scaler = getattr(preprocessor, "scaler", preprocessor)
        mean_val = getattr(scaler, "mean_", None)
        scale_val = getattr(scaler, "scale_", None)
        if mean_val is not None:
            means = np.asarray(mean_val, dtype=np.float32)
            feat_count = len(means)
        if scale_val is not None:
            scales = np.asarray(scale_val, dtype=np.float32)

    c_lines.append(f"#define TINYML_TFLITE_IN_FEATURES {feat_count}")
    c_lines.append(f"#define TINYML_TFLITE_ANOMALY_THRESHOLD {anomaly_threshold:.6f}f\n")

    c_lines.append(f"static const float TINYML_TFLITE_SCALER_MEAN[{feat_count}] = {{")
    c_lines.append(_format_float_1d_array(means, indent=4))
    c_lines.append("};\n")

    c_lines.append(f"static const float TINYML_TFLITE_SCALER_SCALE[{feat_count}] = {{")
    c_lines.append(_format_float_1d_array(scales, indent=4))
    c_lines.append("};\n")

    # Classifier flatbuffer
    if classifier_bytes:
        c_lines.append("// --- TFLite Classifier Model FlatBuffer ---")
        c_lines.append(format_bytes_as_c_array(classifier_bytes, "g_classifier_tflite"))
    else:
        c_lines.append("// Khong co Classifier TFLite FlatBuffer")
        c_lines.append("const unsigned int g_classifier_tflite_len = 0;")
        c_lines.append("const unsigned char g_classifier_tflite[] = {0x00};\n")

    # Anomaly flatbuffer
    if anomaly_bytes:
        c_lines.append("// --- TFLite Anomaly Detector Model FlatBuffer ---")
        c_lines.append(format_bytes_as_c_array(anomaly_bytes, "g_anomaly_tflite"))
    else:
        c_lines.append("// Khong co Anomaly Detector TFLite FlatBuffer")
        c_lines.append("const unsigned int g_anomaly_tflite_len = 0;")
        c_lines.append("const unsigned char g_anomaly_tflite[] = {0x00};\n")

    c_lines.append("#endif // TINYML_TFLITE_ARRAY_H")
    return "\n".join(c_lines)


def export_tinyml_suite(
    anomaly_model: Any,
    classifier_model: Any,
    preprocessor: Any,
    output_dir: str,
    esp_firmware_dir: Optional[str] = None,
    label_names: Optional[List[str]] = None
) -> Dict[str, str]:
    """
    Xuất trọn bộ Deep Learning TFLite FlatBuffer và C FlatBuffer Header:
    1. classifier_dnn.tflite (hoặc classifier_lstm.tflite)
    2. anomaly_autoencoder.tflite
    3. tinyml_tflite_array.h (C Header chứa mảng FlatBuffer + Scaler)
    """
    os.makedirs(output_dir, exist_ok=True)
    generated_files = {}

    in_features = len(getattr(preprocessor, "feature_names", [])) or 56
    num_classes = len(label_names) if label_names else 15

    # 1. Trích xuất và xuất Classifier TFLite FlatBuffer
    classifier_tflite_bytes: Optional[bytes] = None
    if is_deep_learning_model(classifier_model):
        try:
            clf_name = "classifier_lstm.tflite" if is_lstm_model(classifier_model) else "classifier_dnn.tflite"
            clf_tflite_path = os.path.join(output_dir, clf_name)
            classifier_tflite_bytes = convert_pytorch_classifier_to_tflite(
                classifier_model=classifier_model,
                in_features=in_features,
                num_classes=num_classes,
                output_path=clf_tflite_path
            )
            generated_files["classifier_tflite"] = clf_tflite_path
            # Cũng tạo liên kết symlink hoặc copy ra classifier_dnn.tflite nếu firmware mong muốn tên mặc định
            if clf_name != "classifier_dnn.tflite":
                default_clf_path = os.path.join(output_dir, "classifier_dnn.tflite")
                with open(default_clf_path, "wb") as f:
                    f.write(classifier_tflite_bytes)
        except Exception as e:
            print(f"[TFLiteExporter] [Canh bao] Khong the xuat Classifier TFLite: {e}")

    # 2. Trích xuất và xuất Autoencoder TFLite FlatBuffer
    anomaly_tflite_bytes: Optional[bytes] = None
    anomaly_threshold = float(getattr(anomaly_model, "threshold_", 0.50))
    if is_deep_learning_model(anomaly_model):
        try:
            ae_tflite_path = os.path.join(output_dir, "anomaly_autoencoder.tflite")
            anomaly_tflite_bytes = convert_pytorch_autoencoder_to_tflite(
                anomaly_model=anomaly_model,
                in_features=in_features,
                latent_dim=getattr(anomaly_model, "latent_dim", 8),
                output_path=ae_tflite_path
            )
            generated_files["anomaly_tflite"] = ae_tflite_path
        except Exception as e:
            print(f"[TFLiteExporter] [Canh bao] Khong the xuat Autoencoder TFLite: {e}")

    # 3. Tạo tinyml_tflite_array.h
    if classifier_tflite_bytes or anomaly_tflite_bytes:
        header_code = generate_tflite_array_header(
            classifier_bytes=classifier_tflite_bytes,
            anomaly_bytes=anomaly_tflite_bytes,
            preprocessor=preprocessor,
            label_names=label_names,
            anomaly_threshold=anomaly_threshold
        )
        h_path = os.path.join(output_dir, "tinyml_tflite_array.h")
        with open(h_path, "w", encoding="utf-8") as f:
            f.write(header_code)
        generated_files["tflite_header"] = h_path
        print(f"[TFLiteExporter] Da xuat TFLite C Header: {h_path}")

    # 4. Đồng bộ các tệp sang firmware ESP32 nếu có chỉ định thư mục
    if esp_firmware_dir and os.path.exists(esp_firmware_dir):
        import shutil
        if "classifier_tflite" in generated_files:
            dest_clf = os.path.join(esp_firmware_dir, "classifier_dnn.tflite")
            try:
                shutil.copy2(generated_files["classifier_tflite"], dest_clf)
                generated_files["esp32_classifier_tflite"] = dest_clf
                print(f"[TFLiteExporter] Da dong bo classifier_dnn.tflite sang: {dest_clf}")
            except Exception as e:
                print(f"[TFLiteExporter] Canh bao dong bo classifier tflite: {e}")

        if "anomaly_tflite" in generated_files:
            dest_ae = os.path.join(esp_firmware_dir, "anomaly_autoencoder.tflite")
            try:
                shutil.copy2(generated_files["anomaly_tflite"], dest_ae)
                generated_files["esp32_anomaly_tflite"] = dest_ae
                print(f"[TFLiteExporter] Da dong bo anomaly_autoencoder.tflite sang: {dest_ae}")
            except Exception as e:
                print(f"[TFLiteExporter] Canh bao dong bo autoencoder tflite: {e}")

        if "tflite_header" in generated_files:
            dest_h = os.path.join(esp_firmware_dir, "tinyml_tflite_array.h")
            try:
                shutil.copy2(generated_files["tflite_header"], dest_h)
                generated_files["esp32_tflite_header"] = dest_h
                print(f"[TFLiteExporter] Da dong bo tinyml_tflite_array.h sang: {dest_h}")
            except Exception as e:
                print(f"[TFLiteExporter] Canh bao dong bo tinyml_tflite_array.h: {e}")

    return generated_files
