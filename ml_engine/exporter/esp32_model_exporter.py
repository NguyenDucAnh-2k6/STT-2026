"""Resource-budgeted, exact classical ML export. Unsupported models fail explicitly.

Input is encoded numeric features in fitted order; raw categorical vocabularies
and protocol extraction are separate contracts, never replaced by zero padding.
"""
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest, RandomForestClassifier
from sklearn.ensemble._iforest import _average_path_length
from sklearn.linear_model import LogisticRegression
from sklearn.svm import OneClassSVM
from sklearn.tree import DecisionTreeClassifier


def unwrap_model(model: Any) -> Any:
    return getattr(model, "underlying_estimator", getattr(model, "model", model))


class CModelWriter:
    def __init__(self, max_constant_bytes: int) -> None:
        self.code: list[str] = []
        self.constant_bytes = 0
        self.max_constant_bytes = max_constant_bytes
        self.tree_count = 0
        self.node_count = 0

    @staticmethod
    def number(value: float) -> str:
        if not np.isfinite(value):
            raise ValueError("Cannot export non-finite model constants")
        return format(float(value), ".17g")

    def array(self, name: str, values: Any, kind: str = "double") -> None:
        items = np.asarray(values).ravel()
        widths = {"double": 8, "float": 4, "int16_t": 2, "int32_t": 4, "int8_t": 1}
        if kind.startswith("int"):
            bits = widths[kind] * 8
            if ((items < -(2 ** (bits - 1))) | (items >= 2 ** (bits - 1))).any():
                raise ValueError(f"Integer table overflow: {name}")
        self.constant_bytes += len(items) * widths[kind]
        if self.constant_bytes > self.max_constant_bytes:
            raise ValueError(f"Model needs more than configured {self.max_constant_bytes} constant bytes; no trees were truncated")
        self.code.append(f"static const {kind} {name}[] = {{" + ",".join(self.number(v) for v in items) + "};\n")

    def tree(self, prefix: str, estimator: Any, mapping: Any = None) -> None:
        tree = estimator.tree_
        if tree.node_count >= 32768 or tree.max_depth >= 64:
            raise ValueError("Tree exceeds int16 node/depth budget; retrain a compact model explicitly")
        features = tree.feature.copy()
        if mapping is not None:
            mask = features >= 0
            features[mask] = np.asarray(mapping)[features[mask]]
        for suffix, values, kind in [("left", tree.children_left, "int16_t"), ("right", tree.children_right, "int16_t"),
                                     ("feature", features, "int8_t"), ("threshold", tree.threshold, "double")]:
            self.array(prefix + "_" + suffix, values, kind)
        self.code.append(f"""static inline int {prefix}_leaf(const float* f) {{
  int node=0;
  for(int depth=0;depth<64;++depth) {{
    if({prefix}_left[node]<0) return node;
    node=f[{prefix}_feature[node]]<={prefix}_threshold[node] ? {prefix}_left[node] : {prefix}_right[node];
  }}
  return -1;
}}
""")
        self.tree_count += 1
        self.node_count += tree.node_count


def _class_indices(model: Any, labels: list[str]) -> np.ndarray:
    indices = []
    for label in model.classes_:
        if isinstance(label, (str, np.str_)):
            indices.append(labels.index(str(label)))
        elif float(label).is_integer() and 0 <= int(label) < len(labels):
            indices.append(int(label))
        else:
            raise ValueError("Classifier classes do not match declared labels")
    if len(set(indices)) != len(indices):
        raise ValueError("Duplicate label mapping")
    return np.asarray(indices, dtype=int)


def export_classifier_to_esp32(classifier: Any, labels: list[str], writer: CModelWriter) -> None:
    """Emit DT/RF/ExtraTrees or LogisticRegression, without approximation/truncation."""
    model = unwrap_model(classifier)
    indices = _class_indices(model, labels)
    if isinstance(model, (DecisionTreeClassifier, RandomForestClassifier, ExtraTreesClassifier)):
        if model.n_outputs_ != 1:
            raise ValueError("Multi-output classifiers are not supported")
        trees = model.estimators_ if isinstance(model, (RandomForestClassifier, ExtraTreesClassifier)) else [model]
        calls = []
        for index, estimator in enumerate(trees):
            prefix = f"esp32_clf_{index}"
            writer.tree(prefix, estimator)
            # Store leaf distributions only. Branch nodes never need probabilities.
            leaves = np.flatnonzero(estimator.tree_.children_left < 0)
            leaf_map = np.full(estimator.tree_.node_count, -1, dtype=int)
            leaf_map[leaves] = np.arange(len(leaves))
            probabilities = np.zeros((len(leaves), len(labels)))
            for row, node in enumerate(leaves):
                value = estimator.tree_.value[node][0]
                if value.sum() <= 0:
                    raise ValueError("Empty classifier leaf")
                probabilities[row, indices] = value / value.sum()
            writer.array(prefix + "_row", leaf_map, "int16_t")
            # Double accumulation preserves sklearn's mean-of-distributions semantics.
            writer.array(prefix + "_probabilities", probabilities, "double")
            calls.append(f"  leaf={prefix}_leaf(f); if(leaf<0) return false; row={prefix}_row[leaf];\n"
                         f"  for(int c=0;c<ESP32_PACKET_CLASS_COUNT;++c) sums[c]+={prefix}_probabilities[row*ESP32_PACKET_CLASS_COUNT+c];\n")
        writer.code.append("static inline bool esp32_classifier(const float* f,float* out) {\n"
            "  double sums[ESP32_PACKET_CLASS_COUNT]={0}; int leaf,row;\n" + "".join(calls) +
            f"  for(int c=0;c<ESP32_PACKET_CLASS_COUNT;++c) out[c]=(float)(sums[c]/{len(trees)}.0);\n  return true;\n}}\n")
    elif isinstance(model, LogisticRegression):
        writer.array("esp32_lr_weights", model.coef_)
        writer.array("esp32_lr_bias", model.intercept_)
        writer.array("esp32_lr_classes", indices, "int16_t")
        rows = model.coef_.shape[0]
        binary = rows == 1 and len(indices) == 2
        ovr = getattr(model, "multi_class", None) == "ovr" or model.solver == "liblinear"
        writer.code.append(f"""static inline bool esp32_classifier(const float* f,float* out) {{
  double logits[{rows}];
  for(int c=0;c<ESP32_PACKET_CLASS_COUNT;++c) out[c]=0;
  for(int c=0;c<{rows};++c) {{
    logits[c]=esp32_lr_bias[c];
    for(int j=0;j<ESP32_PACKET_FEATURE_COUNT;++j) logits[c]+=esp32_lr_weights[c*ESP32_PACKET_FEATURE_COUNT+j]*f[j];
  }}
""")
        if binary:
            writer.code.append("  double p=1/(1+exp(-logits[0])); out[esp32_lr_classes[0]]=(float)(1-p); out[esp32_lr_classes[1]]=(float)p;\n")
        else:
            writer.code.append(f"  double total=0,maximum=logits[0]; for(int c=1;c<{rows};++c) if(logits[c]>maximum) maximum=logits[c];\n")
            writer.code.append(f"  for(int c=0;c<{rows};++c) {{ logits[c]=" +
                ("1/(1+exp(-logits[c]))" if ovr else "exp(logits[c]-maximum)") + "; total+=logits[c]; }\n")
            writer.code.append(f"  if(total<=0 || !isfinite(total)) return false; for(int c=0;c<{rows};++c) out[esp32_lr_classes[c]]=(float)(logits[c]/total);\n")
        writer.code.append("  return true;\n}\n")
    else:
        raise NotImplementedError(f"No verified ESP32 classifier exporter for {type(model).__name__}; no surrogate model is substituted")


def export_anomaly_to_esp32(anomaly: Any, metadata: dict[str, Any], writer: CModelWriter) -> None:
    """Emit IF, RBF OneClassSVM or EllipticEnvelope score functions exactly."""
    model = unwrap_model(anomaly)
    if isinstance(model, IsolationForest):
        calls = []
        for index, (estimator, mapping) in enumerate(zip(model.estimators_, model.estimators_features_)):
            prefix = f"esp32_iso_{index}"
            writer.tree(prefix, estimator, mapping)
            depths = np.zeros(estimator.tree_.node_count)
            stack = [(0, 0)]
            while stack:
                node, depth = stack.pop()
                depths[node] = depth
                if estimator.tree_.children_left[node] >= 0:
                    stack += [(estimator.tree_.children_left[node], depth+1), (estimator.tree_.children_right[node], depth+1)]
            writer.array(prefix + "_path", depths + _average_path_length(estimator.tree_.n_node_samples))
            calls.append(f"  leaf={prefix}_leaf(f); if(leaf<0) return false; sum+={prefix}_path[leaf];\n")
        denominator = len(model.estimators_) * float(_average_path_length([model.max_samples_])[0])
        if denominator <= 0:
            raise ValueError("IsolationForest requires at least two normal training samples")
        minimum, maximum = float(metadata["isolation_score_min"]), float(metadata["isolation_score_max"])
        writer.code.append("static inline bool esp32_detector(const float* f,double* sample,double* score) {\n  double sum=0; int leaf;\n" +
            "".join(calls) + f"  *sample=-pow(2.0,-sum/{writer.number(denominator)});\n"
            f"  double distance=({writer.number(maximum)}-*sample)/{writer.number(max(maximum-minimum,1e-6))};\n"
            "  *score=1/(1+exp(-4*(distance-.5))); return isfinite(*sample)&&isfinite(*score);\n}\n")
    elif isinstance(model, OneClassSVM):
        if model.kernel != "rbf":
            raise NotImplementedError("Only fitted RBF OneClassSVM is verified by this exporter")
        writer.array("esp32_svm_vectors", model.support_vectors_)
        writer.array("esp32_svm_coefficients", model.dual_coef_)
        writer.code.append(f"""static inline bool esp32_detector(const float* f,double* sample,double* score) {{
  double sum=0;
  for(int i=0;i<{len(model.support_vectors_)};++i) {{
    double distance=0;
    for(int j=0;j<ESP32_PACKET_FEATURE_COUNT;++j) {{ double d=f[j]-esp32_svm_vectors[i*ESP32_PACKET_FEATURE_COUNT+j]; distance+=d*d; }}
    sum+=esp32_svm_coefficients[i]*exp(-{writer.number(model._gamma)}*distance);
  }}
  *sample=sum; *score=1/(1+exp(sum+{writer.number(model.intercept_[0])}));
  return isfinite(*sample)&&isfinite(*score);
}}
""")
    elif isinstance(model, EllipticEnvelope):
        writer.array("esp32_ellipse_mean", model.location_)
        writer.array("esp32_ellipse_precision", model.precision_)
        threshold = float(-model.offset_)
        writer.code.append(f"""static inline bool esp32_detector(const float* f,double* sample,double* score) {{
  double d[ESP32_PACKET_FEATURE_COUNT],distance=0;
  for(int i=0;i<ESP32_PACKET_FEATURE_COUNT;++i) d[i]=f[i]-esp32_ellipse_mean[i];
  for(int i=0;i<ESP32_PACKET_FEATURE_COUNT;++i) for(int j=0;j<ESP32_PACKET_FEATURE_COUNT;++j)
    distance+=d[i]*esp32_ellipse_precision[i*ESP32_PACKET_FEATURE_COUNT+j]*d[j];
  *sample=-distance; *score=1/(1+exp(-2*(distance-{writer.number(threshold)})/{writer.number(max(threshold,1e-4))}));
  return isfinite(*sample)&&isfinite(*score);
}}
""")
    else:
        raise NotImplementedError(f"No verified ESP32 anomaly exporter for {type(model).__name__}; unsupported is not Normal")


def export_model_header(classifier: Any, anomaly: Any, scaler: Any, feature_names: list[str],
                        labels: list[str], metadata: dict[str, Any], path: Path,
                        max_constant_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    """Export fitted estimators + scaler in a common zero-heap C/C++ interface."""
    classifier, anomaly = unwrap_model(classifier), unwrap_model(anomaly)
    count = len(feature_names)
    if not 1 <= count <= 127 or len(set(feature_names)) != count:
        raise ValueError("Invalid feature order/count")
    identifiers = [name.upper().replace(".", "_") for name in feature_names]
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name) for name in feature_names) or len(set(identifiers)) != count:
        raise ValueError("Feature names must form distinct valid C identifiers")
    if any(model.n_features_in_ != count for model in (classifier, anomaly, scaler)):
        raise ValueError("Model/scaler/feature order mismatch")
    if not labels or len(set(labels)) != len(labels) or max_constant_bytes <= 0:
        raise ValueError("Invalid label order or memory budget")
    writer = CModelWriter(max_constant_bytes)
    writer.code += ["// Generated by esp32_model_exporter. Input: encoded numeric vector. Do not edit.\n#ifndef ESP32_PACKET_MODEL_H\n#define ESP32_PACKET_MODEL_H\n",
        "#include <stdint.h>\n#include <stdbool.h>\n#include <math.h>\n",
        f"#define ESP32_PACKET_FEATURE_COUNT {count}\n#define ESP32_PACKET_CLASS_COUNT {len(labels)}\n",
        f"#define ESP32_PACKET_PROFILE {json.dumps(metadata['profile'])}\n#define ESP32_PACKET_MODEL_ID {json.dumps(metadata['artifact_id'])}\n",
        f"#define ESP32_PACKET_THRESHOLD {writer.number(metadata['anomaly_threshold'])}\n",
        f"#define ESP32_PACKET_MODEL_NAME {json.dumps(type(classifier).__name__ + ' + ' + type(anomaly).__name__)}\n"]
    for index, name in enumerate(feature_names):
        writer.code.append(f"#define ESP32_F_{name.upper().replace('.', '_')} {index}\n")
    writer.code += ["static const char* const ESP32_PACKET_FEATURE_NAMES[]={" + ",".join(map(json.dumps, feature_names)) + "};\n",
                    "static const char* const ESP32_PACKET_LABELS[]={" + ",".join(map(json.dumps, labels)) + "};\n"]
    means = scaler.mean_ if scaler.with_mean else np.zeros(count)
    scales = scaler.scale_ if scaler.with_std else np.ones(count)
    if np.asarray(scales).shape != (count,) or (np.asarray(scales) <= 0).any():
        raise ValueError("Invalid fitted scaler")
    writer.array("esp32_mean", means)
    writer.array("esp32_scale", scales)
    writer.code.append("""static inline bool esp32_preprocess(const float* raw,float* scaled) {
  if(!raw || !scaled) return false;
  for(int i=0;i<ESP32_PACKET_FEATURE_COUNT;++i) {
    if(!isfinite(raw[i])) return false;
    float centered=(float)((double)raw[i]-esp32_mean[i]);
    scaled[i]=(float)((double)centered/esp32_scale[i]);
    if(!isfinite(scaled[i])) return false;
  }
  return true;
}
""")
    export_classifier_to_esp32(classifier, labels, writer)
    export_anomaly_to_esp32(anomaly, metadata, writer)
    writer.code.append("""static inline bool esp32_predict_packet(const float* raw,float* probabilities,float* anomaly_score,float* score_sample) {
  float f[ESP32_PACKET_FEATURE_COUNT]; double sample,score;
  if(!probabilities || !anomaly_score || !score_sample || !esp32_preprocess(raw,f)) return false;
  if(!esp32_classifier(f,probabilities) || !esp32_detector(f,&sample,&score)) return false;
  *anomaly_score=(float)score; *score_sample=(float)sample;
  return isfinite(*anomaly_score)&&isfinite(*score_sample);
}
#endif
""")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(writer.code), encoding="utf-8")
    return {"classifier": type(classifier).__name__, "anomaly_detector": type(anomaly).__name__,
        "features": count, "classes": len(labels), "exported_trees": writer.tree_count, "exported_nodes": writer.node_count,
        "estimated_numeric_constant_bytes": writer.constant_bytes, "header_source_bytes": path.stat().st_size,
        "input_domain": "encoded_numeric_features", "categorical_vocabulary_in_header": False,
        "hardware_flash_ram_measured": False, "trees_truncated": False}
