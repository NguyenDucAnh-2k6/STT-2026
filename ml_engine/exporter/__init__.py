"""
TinyML (ML) & TFLite (DL) Exporter Package
===========================================
Cung cấp 2 handler chuyên biệt:
1. tinyml_exporter (Classical Machine Learning Handler):
   - Decision Tree, Random Forest, Extra Trees, Isolation Forest
   - Logistic Regression
   - One-Class SVM, Elliptic Envelope, Local Outlier Factor (LOF)
   - Xuất mã C thuần túy (tinyml_model.h) zero-heap cho vi điều khiển ESP32.
2. tflite_exporter (Deep Learning Handler):
   - EdgeDeepNet (DNN with folded BatchNorm)
   - EdgeLSTMNet (Bi-LSTM / LSTM sequence classifier)
   - AutoencoderNet (Symmetric Deep Autoencoder MSE)
   - Xuất file FlatBuffer (.tflite) và mảng C FlatBuffer (tinyml_tflite_array.h).
"""

from .tinyml_exporter import (
    export_model_to_c_header,
    export_decision_tree_to_header,
    generate_classifier_c,
    generate_anomaly_detector_c
)
from .tree_exporter import (
    tree_to_c_code,
    _generate_decision_tree_classifier_c,
    _generate_forest_classifier_c,
    _generate_isolation_forest_c
)
from .linear_exporter import (
    _generate_logistic_regression_c
)
from .kernel_density_exporter import (
    _generate_one_class_svm_c,
    _generate_elliptic_envelope_c,
    _generate_lof_c
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
from .tflite_exporter import (
    convert_keras_to_tflite,
    convert_pytorch_classifier_to_tflite,
    convert_pytorch_autoencoder_to_tflite,
    generate_tflite_array_header,
    format_bytes_as_c_array,
    export_tinyml_suite
)

__all__ = [
    # ML Handler (TinyML C)
    "export_model_to_c_header",
    "export_decision_tree_to_header",
    "generate_classifier_c",
    "generate_anomaly_detector_c",
    "tree_to_c_code",
    "_generate_decision_tree_classifier_c",
    "_generate_forest_classifier_c",
    "_generate_isolation_forest_c",
    "_generate_logistic_regression_c",
    "_generate_one_class_svm_c",
    "_generate_elliptic_envelope_c",
    "_generate_lof_c",
    # DL Handler (TFLite FlatBuffer)
    "is_deep_learning_model",
    "is_lstm_model",
    "extract_folded_pytorch_dnn_weights",
    "extract_pytorch_lstm_weights",
    "extract_pytorch_autoencoder_weights",
    "build_keras_dnn_model",
    "build_keras_lstm_model",
    "build_keras_autoencoder_model",
    "convert_keras_to_tflite",
    "convert_pytorch_classifier_to_tflite",
    "convert_pytorch_autoencoder_to_tflite",
    "generate_tflite_array_header",
    "format_bytes_as_c_array",
    "export_tinyml_suite"
]
