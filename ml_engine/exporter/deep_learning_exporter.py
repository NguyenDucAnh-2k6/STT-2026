"""
Deep Learning Model Exporter & Graph Parser
============================================
Chỉ dẫn module:
- Module này chuyên trách phân tích computation graph và trích xuất trọng số thực tế 1:1
  từ các mô hình Deep Learning PyTorch:
  1. EdgeDeepNet: Mạng nơ-ron sâu dạng bảng (DNN) với kỹ thuật gập toán học BatchNorm1d vào Linear.
  2. EdgeLSTMNet: Mạng nơ-ron hồi quy chuỗi thời gian (Bi-LSTM + FC Layers) cho phân loại chuỗi.
  3. AutoencoderNet: Mạng nơ-ron Autoencoder đối xứng phát hiện bất thường không giám sát (MSE).
- Xây dựng mô hình Keras tương ứng với trọng số chính xác để phục vụ xuất TensorFlow Lite (TFLite).
- Tuyệt đối KHÔNG có fallback ngầm sang Decision Tree hoặc các hàm heuristic tự bịa.
"""

from typing import List, Tuple, Dict, Any, Optional
import numpy as np

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False


def is_deep_learning_model(model: Any) -> bool:
    """Kiểm tra một đối tượng mô hình có phải là Deep Learning hay không."""
    if model is None:
        return False
    if getattr(model, "is_deep_learning", False):
        return True
    raw = getattr(model, "underlying_estimator", getattr(model, "model", getattr(model, "net", model)))
    if TORCH_AVAILABLE and isinstance(raw, nn.Module):
        return True
    type_name = type(model).__name__.lower()
    raw_name = type(raw).__name__.lower()
    dl_keywords = ("deep", "dnn", "lstm", "autoencoder", "neural", "torch", "mlp")
    return any(k in type_name or k in raw_name for k in dl_keywords)


def is_lstm_model(model: Any) -> bool:
    """Kiểm tra mô hình có chứa thành phần Recurrent / LSTM hay không."""
    raw = getattr(model, "underlying_estimator", getattr(model, "model", getattr(model, "net", model)))
    if hasattr(raw, "lstm") or getattr(model, "is_timeseries", False):
        return True
    type_name = type(raw).__name__.lower()
    return "lstm" in type_name or "recurrent" in type_name


def extract_folded_pytorch_dnn_weights(
    classifier_model: Any
) -> Tuple[List[Tuple[np.ndarray, np.ndarray]], int, int]:
    """
    Trích xuất và gập toán học toàn bộ các tầng Linear + BatchNorm1d từ EdgeDeepNet (PyTorch).
    Công thức gập BatchNorm1d:
      scale = gamma / sqrt(var + eps)
      W_folded = W * scale[:, newaxis]
      b_folded = (b - mean) * scale + beta
    Trả về: (danh sách (W, b) cho mỗi tầng, in_features, num_classes)
    """
    raw_model = getattr(classifier_model, "underlying_estimator", getattr(classifier_model, "model", classifier_model))
    net = getattr(classifier_model, "net", raw_model)

    if not TORCH_AVAILABLE or not hasattr(net, "net"):
        raise ValueError(
            f"Không tìm thấy computation graph PyTorch hợp lệ trong mô hình phân loại: {type(classifier_model).__name__}."
        )

    net.eval()
    layers = list(net.net.children())

    folded_weights: List[Tuple[np.ndarray, np.ndarray]] = []
    i = 0
    in_features: Optional[int] = None

    while i < len(layers):
        layer = layers[i]
        if isinstance(layer, nn.Linear):
            if in_features is None:
                in_features = layer.in_features

            w = layer.weight.detach().cpu().numpy().copy()
            b = layer.bias.detach().cpu().numpy().copy() if layer.bias is not None else np.zeros(layer.out_features, dtype=np.float32)

            # Kiểm tra nếu ngay sau là BatchNorm1d để gập vào Linear
            if i + 1 < len(layers) and isinstance(layers[i + 1], nn.BatchNorm1d):
                bn = layers[i + 1]
                gamma = bn.weight.detach().cpu().numpy()
                beta = bn.bias.detach().cpu().numpy()
                mean = bn.running_mean.detach().cpu().numpy()
                var = bn.running_var.detach().cpu().numpy()
                eps = bn.eps

                scale = gamma / np.sqrt(var + eps)
                w = w * scale[:, np.newaxis]
                b = (b - mean) * scale + beta
                i += 2
            else:
                i += 1

            folded_weights.append((w, b))
        else:
            i += 1

    if not folded_weights:
        raise ValueError("Không thể trích xuất bất kỳ tầng Linear nào từ EdgeDeepNet.")

    num_classes = folded_weights[-1][0].shape[0]
    return folded_weights, in_features or 56, num_classes


def extract_pytorch_lstm_weights(
    classifier_model: Any
) -> Dict[str, Any]:
    """
    Trích xuất toàn bộ trọng số của EdgeLSTMNet (PyTorch):
    - Bi-LSTM 2 tầng (weight_ih, weight_hh, bias_ih, bias_hh cho cả 2 hướng forward & reverse).
    - FC layers với BatchNorm gập sẵn vào Linear.
    """
    raw_model = getattr(classifier_model, "underlying_estimator", getattr(classifier_model, "model", classifier_model))
    net = getattr(classifier_model, "net", raw_model)

    if not TORCH_AVAILABLE or not hasattr(net, "lstm") or not hasattr(net, "fc"):
        raise ValueError(
            f"Không tìm thấy cấu trúc EdgeLSTMNet hợp lệ (thiếu .lstm hoặc .fc): {type(classifier_model).__name__}."
        )

    net.eval()
    lstm = net.lstm
    fc = net.fc

    in_features = lstm.input_size
    hidden_dim = lstm.hidden_size
    num_layers = lstm.num_layers
    bidirectional = lstm.bidirectional

    # 1. Trích xuất trọng số các tầng LSTM
    lstm_layers_weights = []
    for l in range(num_layers):
        l_weights = {}
        # Forward weights
        w_ih = getattr(lstm, f"weight_ih_l{l}").detach().cpu().numpy().copy()
        w_hh = getattr(lstm, f"weight_hh_l{l}").detach().cpu().numpy().copy()
        b_ih = getattr(lstm, f"bias_ih_l{l}").detach().cpu().numpy().copy()
        b_hh = getattr(lstm, f"bias_hh_l{l}").detach().cpu().numpy().copy()
        l_weights["forward"] = {
            "kernel": w_ih.T,
            "recurrent_kernel": w_hh.T,
            "bias": b_ih + b_hh
        }

        if bidirectional:
            w_ih_rev = getattr(lstm, f"weight_ih_l{l}_reverse").detach().cpu().numpy().copy()
            w_hh_rev = getattr(lstm, f"weight_hh_l{l}_reverse").detach().cpu().numpy().copy()
            b_ih_rev = getattr(lstm, f"bias_ih_l{l}_reverse").detach().cpu().numpy().copy()
            b_hh_rev = getattr(lstm, f"bias_hh_l{l}_reverse").detach().cpu().numpy().copy()
            l_weights["reverse"] = {
                "kernel": w_ih_rev.T,
                "recurrent_kernel": w_hh_rev.T,
                "bias": b_ih_rev + b_hh_rev
            }
        lstm_layers_weights.append(l_weights)

    # 2. Trích xuất FC layers (fold BatchNorm nếu có)
    fc_layers = list(fc.children())
    fc_folded: List[Tuple[np.ndarray, np.ndarray]] = []
    j = 0
    while j < len(fc_layers):
        layer = fc_layers[j]
        if isinstance(layer, nn.Linear):
            w = layer.weight.detach().cpu().numpy().copy()
            b = layer.bias.detach().cpu().numpy().copy() if layer.bias is not None else np.zeros(layer.out_features, dtype=np.float32)

            if j + 1 < len(fc_layers) and isinstance(fc_layers[j + 1], nn.BatchNorm1d):
                bn = fc_layers[j + 1]
                gamma = bn.weight.detach().cpu().numpy()
                beta = bn.bias.detach().cpu().numpy()
                mean = bn.running_mean.detach().cpu().numpy()
                var = bn.running_var.detach().cpu().numpy()
                eps = bn.eps

                scale = gamma / np.sqrt(var + eps)
                w = w * scale[:, np.newaxis]
                b = (b - mean) * scale + beta
                j += 2
            else:
                j += 1
            fc_folded.append((w, b))
        else:
            j += 1

    num_classes = fc_folded[-1][0].shape[0] if fc_folded else 15

    return {
        "in_features": in_features,
        "hidden_dim": hidden_dim,
        "num_layers": num_layers,
        "bidirectional": bidirectional,
        "num_classes": num_classes,
        "lstm_layers": lstm_layers_weights,
        "fc_folded": fc_folded
    }


def extract_pytorch_autoencoder_weights(
    anomaly_model: Any
) -> Tuple[Dict[str, np.ndarray], int, int, float, float, float]:
    """
    Trích xuất toàn bộ trọng số của AutoencoderNet (PyTorch).
    Trả về: (dict các mảng W và b, in_features, latent_dim, threshold, min_loss, max_loss)
    """
    raw_model = getattr(anomaly_model, "underlying_estimator", getattr(anomaly_model, "model", anomaly_model))
    net = getattr(anomaly_model, "net", raw_model)

    weights: Dict[str, np.ndarray] = {}
    in_features = getattr(anomaly_model, "in_features", 56)
    latent_dim = getattr(anomaly_model, "latent_dim", 8)
    threshold = getattr(anomaly_model, "threshold_", 0.1)
    min_loss = getattr(anomaly_model, "min_loss_", 0.0)
    max_loss = getattr(anomaly_model, "max_loss_", 1.0)

    if TORCH_AVAILABLE and hasattr(net, "state_dict"):
        net.eval()
        state = net.state_dict()
        for k, v in state.items():
            weights[k] = v.detach().cpu().numpy().copy()
        if "encoder.0.weight" in weights:
            in_features = weights["encoder.0.weight"].shape[1]
        if "encoder.4.weight" in weights:
            latent_dim = weights["encoder.4.weight"].shape[0]
    elif hasattr(anomaly_model, "weights_") and isinstance(anomaly_model.weights_, dict):
        weights = anomaly_model.weights_
        if "encoder.0.weight" in weights:
            in_features = weights["encoder.0.weight"].shape[1]
        if "encoder.4.weight" in weights:
            latent_dim = weights["encoder.4.weight"].shape[0]
    else:
        raise ValueError(
            f"Không tìm thấy trọng số Autoencoder hợp lệ trong mô hình: {type(anomaly_model).__name__}."
        )

    return weights, in_features, latent_dim, float(threshold), float(min_loss), float(max_loss)


def build_keras_dnn_model(
    folded_weights: List[Tuple[np.ndarray, np.ndarray]],
    in_features: int,
    num_classes: int
) -> Any:
    """Xây dựng mô hình Keras tương ứng từ các trọng số đã gập của EdgeDeepNet."""
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow chưa được cài đặt để xây dựng Keras DNN Model.")

    keras_layers = [tf.keras.layers.Input(shape=(in_features,), name="network_features")]
    for idx, (w, b) in enumerate(folded_weights):
        out_dim = w.shape[0]
        if idx < len(folded_weights) - 1:
            keras_layers.append(
                tf.keras.layers.Dense(out_dim, activation=tf.keras.layers.LeakyReLU(0.1), name=f"dense_{idx+1}")
            )
        else:
            keras_layers.append(
                tf.keras.layers.Dense(out_dim, activation="softmax", name="attack_probabilities")
            )

    keras_clf = tf.keras.Sequential(keras_layers, name="EdgeDeepNet_Classifier")
    keras_clf.compile(optimizer="adam", loss="sparse_categorical_crossentropy")

    # Gán trọng số chính xác vào từng tầng Dense
    dense_idx = 0
    for layer in keras_clf.layers:
        if isinstance(layer, tf.keras.layers.Dense):
            w_pt, b_pt = folded_weights[dense_idx]
            layer.set_weights([w_pt.T, b_pt])
            dense_idx += 1

    return keras_clf


def build_keras_lstm_model(
    lstm_data: Dict[str, Any],
    in_features: int,
    num_classes: int,
    window_size: int = 10
) -> Any:
    """Xây dựng mô hình Keras Unrolled LSTM từ các trọng số thực tế của EdgeLSTMNet."""
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow chưa được cài đặt để xây dựng Keras LSTM Model.")

    hidden_dim = lstm_data.get("hidden_dim", 64)
    num_layers = lstm_data.get("num_layers", 2)
    bidirectional = lstm_data.get("bidirectional", True)
    lstm_weights = lstm_data.get("lstm_layers", [])
    fc_weights = lstm_data.get("fc_folded", [])

    inp = tf.keras.Input(shape=(window_size, in_features), batch_size=1, name="network_sequence")
    curr = inp

    # Các tầng LSTM unrolled tĩnh (tương thích 100% với TFLite cho Embedded / ESP32)
    lstm_layers_list = []
    for l_idx in range(num_layers):
        ret_seq = (l_idx < num_layers - 1)
        if bidirectional:
            cell = tf.keras.layers.Bidirectional(
                tf.keras.layers.LSTM(hidden_dim, return_sequences=ret_seq, unroll=True),
                name=f"bi_lstm_{l_idx+1}"
            )
        else:
            cell = tf.keras.layers.LSTM(hidden_dim, return_sequences=ret_seq, unroll=True, name=f"lstm_{l_idx+1}")
        curr = cell(curr)
        lstm_layers_list.append(cell)

    # Các tầng FC
    fc_layers_list = []
    for f_idx, (w, b) in enumerate(fc_weights):
        out_dim = w.shape[0]
        is_last = (f_idx == len(fc_weights) - 1)
        act = "softmax" if is_last else tf.keras.layers.LeakyReLU(0.1)
        d_layer = tf.keras.layers.Dense(out_dim, activation=act, name=f"fc_{f_idx+1}")
        curr = d_layer(curr)
        fc_layers_list.append(d_layer)

    model = tf.keras.Model(inputs=inp, outputs=curr, name="EdgeLSTMNet_Classifier")
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy")

    # Nạp trọng số LSTM
    for l_idx, cell in enumerate(lstm_layers_list):
        if l_idx < len(lstm_weights):
            w_info = lstm_weights[l_idx]
            fwd = w_info["forward"]
            if bidirectional and "reverse" in w_info:
                rev = w_info["reverse"]
                cell.set_weights([
                    fwd["kernel"], fwd["recurrent_kernel"], fwd["bias"],
                    rev["kernel"], rev["recurrent_kernel"], rev["bias"]
                ])
            else:
                cell.set_weights([fwd["kernel"], fwd["recurrent_kernel"], fwd["bias"]])

    # Nạp trọng số FC
    for f_idx, d_layer in enumerate(fc_layers_list):
        if f_idx < len(fc_weights):
            w, b = fc_weights[f_idx]
            d_layer.set_weights([w.T, b])

    return model


def build_keras_autoencoder_model(
    weights: Dict[str, np.ndarray],
    in_features: int,
    latent_dim: int = 8
) -> Any:
    """Xây dựng mô hình Keras Autoencoder đối xứng từ trọng số thực tế của AutoencoderNet."""
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow chưa được cài đặt để xây dựng Keras Autoencoder Model.")

    inp = tf.keras.Input(shape=(in_features,), name="input_features")
    # Encoder
    e1 = tf.keras.layers.Dense(32, activation="relu", name="enc_1")(inp)
    e2 = tf.keras.layers.Dense(16, activation="relu", name="enc_2")(e1)
    bottleneck = tf.keras.layers.Dense(latent_dim, activation="relu", name="latent")(e2)
    # Decoder
    d1 = tf.keras.layers.Dense(16, activation="relu", name="dec_1")(bottleneck)
    d2 = tf.keras.layers.Dense(32, activation="relu", name="dec_2")(d1)
    recon = tf.keras.layers.Dense(in_features, activation="linear", name="reconstruction")(d2)

    keras_ae = tf.keras.Model(inputs=inp, outputs=recon, name="AutoencoderNet_Detector")
    keras_ae.compile(optimizer="adam", loss="mse")

    # Nạp trọng số 1:1 từ PyTorch (lưu ý transposed W do Keras dùng [in, out])
    keras_ae.get_layer("enc_1").set_weights([weights["encoder.0.weight"].T, weights["encoder.0.bias"]])
    keras_ae.get_layer("enc_2").set_weights([weights["encoder.2.weight"].T, weights["encoder.2.bias"]])
    keras_ae.get_layer("latent").set_weights([weights["encoder.4.weight"].T, weights["encoder.4.bias"]])
    keras_ae.get_layer("dec_1").set_weights([weights["decoder.0.weight"].T, weights["decoder.0.bias"]])
    keras_ae.get_layer("dec_2").set_weights([weights["decoder.2.weight"].T, weights["decoder.2.bias"]])
    keras_ae.get_layer("reconstruction").set_weights([weights["decoder.4.weight"].T, weights["decoder.4.bias"]])

    return keras_ae
