"""
Adversarial Evasion Evaluator Module
====================================
Đánh giá định lượng hiệu quả của mẫu tấn công đối kháng trước hệ thống IDS:
1. Tỷ lệ phát hiện cơ sở (Baseline Detection Rate) trên mẫu tấn công gốc.
2. Tỷ lệ phát hiện đối kháng (Adversarial Detection Rate).
3. Tỷ lệ lẩn tránh thành công (Evasion Rate = 100% - Adversarial Detection Rate).
4. Độ lệch đặc trưng trung bình (Mean Feature Perturbation Delta).
"""

import os
import sys
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


class AdversarialEvaluator:
    """
    Bộ đánh giá định lượng năng lực lẩn tránh (Evasion Capability).
    """

    def __init__(
        self,
        isolation_forest_model: Any,
        classifier_model: Optional[Any] = None,
        scaler: Optional[Any] = None,
        feature_names: Optional[List[str]] = None,
        anomaly_threshold: float = 0.5
    ):
        self.iso_forest = isolation_forest_model
        self.classifier = classifier_model
        self.scaler = scaler
        self.feature_names = feature_names or []
        self.anomaly_threshold = anomaly_threshold

    def evaluate(
        self,
        x_orig_mal: np.ndarray,
        x_adv_mal: np.ndarray,
        labels: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Đánh giá đối đầu giữa mẫu gốc và mẫu đối kháng.
        """
        n_samples = len(x_orig_mal)
        if n_samples == 0:
            return {"error": "Empty evaluation dataset"}

        # Áp dụng scaler nếu có và số lượng đặc trưng tương thích
        n_features = x_orig_mal.shape[1]
        scaler_compatible = False
        if self.scaler is not None:
            n_in = getattr(self.scaler, "n_features_in_", None)
            if n_in is None or n_in == n_features:
                scaler_compatible = True

        x_orig_eval = self.scaler.transform(x_orig_mal) if scaler_compatible else x_orig_mal
        x_adv_eval = self.scaler.transform(x_adv_mal) if scaler_compatible else x_adv_mal

        # Kiểm tra tính tương thích của Isolation Forest
        iso_compatible = False
        if self.iso_forest is not None:
            raw_model = getattr(self.iso_forest, "model", self.iso_forest)
            n_in = getattr(raw_model, "n_features_in_", None)
            if n_in is not None and n_in == n_features:
                iso_compatible = True

        if not iso_compatible:
            from sklearn.ensemble import IsolationForest
            print(f"[*] Khởi tạo Benchmark Isolation Forest phù hợp với {n_features} đặc trưng...")
            self.iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            self.iso_forest.fit(x_orig_eval)

        # 1. Đánh giá trên Tier 1 (Isolation Forest)
        # Isolation Forest trả về: 1 (Normal), -1 (Anomaly)
        preds_orig_iso = self.iso_forest.predict(x_orig_eval)
        preds_adv_iso = self.iso_forest.predict(x_adv_eval)

        # Đếm số mẫu bị phát hiện là Anomaly (-1)
        detected_orig_iso = np.sum(preds_orig_iso == -1)
        detected_adv_iso = np.sum(preds_adv_iso == -1)

        iso_baseline_rate = (detected_orig_iso / n_samples) * 100.0
        iso_adv_detection_rate = (detected_adv_iso / n_samples) * 100.0
        iso_evasion_rate = 100.0 - iso_adv_detection_rate

        # Điểm Anomaly Score (decision_function càng âm càng bất thường)
        if hasattr(self.iso_forest, "decision_function"):
            scores_orig = self.iso_forest.decision_function(x_orig_eval)
            scores_adv = self.iso_forest.decision_function(x_adv_eval)
        elif hasattr(self.iso_forest, "score_samples"):
            scores_orig = self.iso_forest.score_samples(x_orig_eval)
            scores_adv = self.iso_forest.score_samples(x_adv_eval)
        else:
            scores_orig = np.zeros(n_samples)
            scores_adv = np.zeros(n_samples)

        # 2. Đánh giá trên Tier 2 (Attack Classifier nếu có)
        clf_baseline_rate = None
        clf_adv_detection_rate = None
        clf_evasion_rate = None

        clf_compatible = False
        if self.classifier is not None and hasattr(self.classifier, "predict"):
            raw_clf = getattr(self.classifier, "model", self.classifier)
            n_in = getattr(raw_clf, "n_features_in_", None)
            if n_in is not None and n_in == n_features:
                clf_compatible = True

        if clf_compatible:
            preds_orig_clf = self.classifier.predict(x_orig_eval)
            preds_adv_clf = self.classifier.predict(x_adv_eval)

            # Mẫu được coi là "bị phát hiện" nếu khác nhãn 0 (Normal)
            detected_orig_clf = np.sum(preds_orig_clf != 0)
            detected_adv_clf = np.sum(preds_adv_clf != 0)

            clf_baseline_rate = (detected_orig_clf / n_samples) * 100.0
            clf_adv_detection_rate = (detected_adv_clf / n_samples) * 100.0
            clf_evasion_rate = 100.0 - clf_adv_detection_rate

        # 3. Phân tích độ lệch đặc trưng (Perturbation Analysis)
        abs_diff = np.abs(x_adv_mal - x_orig_mal)
        mean_perturbation = np.mean(abs_diff, axis=0)

        feature_shifts = {}
        if self.feature_names and len(self.feature_names) == x_orig_mal.shape[1]:
            for i, name in enumerate(self.feature_names):
                orig_m = float(np.mean(x_orig_mal[:, i]))
                adv_m = float(np.mean(x_adv_mal[:, i]))
                shift = float(mean_perturbation[i])
                feature_shifts[name] = {
                    "orig_mean": round(orig_m, 4),
                    "adv_mean": round(adv_m, 4),
                    "mean_delta": round(shift, 4)
                }

        results = {
            "total_samples": n_samples,
            "isolation_forest": {
                "baseline_detection_rate": round(iso_baseline_rate, 2),
                "adversarial_detection_rate": round(iso_adv_detection_rate, 2),
                "evasion_rate": round(iso_evasion_rate, 2),
                "mean_orig_score": round(float(np.mean(scores_orig)), 4),
                "mean_adv_score": round(float(np.mean(scores_adv)), 4)
            },
            "classifier": {
                "baseline_detection_rate": round(clf_baseline_rate, 2) if clf_baseline_rate is not None else None,
                "adversarial_detection_rate": round(clf_adv_detection_rate, 2) if clf_adv_detection_rate is not None else None,
                "evasion_rate": round(clf_evasion_rate, 2) if clf_evasion_rate is not None else None
            },
            "feature_shifts": feature_shifts
        }

        return results

    def print_summary(self, results: Dict[str, Any]):
        """In bảng tổng kết kết quả đánh giá đối kháng chuyên nghiệp."""
        print("\n" + "=" * 70)
        print("          BÁO CÁO ĐÁNH GIÁ TẤN CÔNG ĐỐI KHÁNG (GAN EVASION)          ")
        print("=" * 70)
        print(f"Tổng số mẫu kiểm thử: {results['total_samples']}")

        iso = results["isolation_forest"]
        print("\n[Tier 1: Isolation Forest (Unsupervised Anomaly Detector)]")
        print(f"  - Tỷ lệ phát hiện ban đầu (Baseline Detection Rate):    {iso['baseline_detection_rate']}%")
        print(f"  - Tỷ lệ phát hiện sau đối kháng (Adversarial Detection): {iso['adversarial_detection_rate']}%")
        print(f"  --> TỶ LỆ LẨN TRÁNH THÀNH CÔNG (Evasion Rate):           {iso['evasion_rate']}%")
        print(f"  - Điểm bất thường TB: Gốc = {iso['mean_orig_score']} -> Đối kháng = {iso['mean_adv_score']}")

        clf = results["classifier"]
        if clf["baseline_detection_rate"] is not None:
            print("\n[Tier 2: Attack Classifier (Supervised Detection)]")
            print(f"  - Tỷ lệ phát hiện ban đầu:    {clf['baseline_detection_rate']}%")
            print(f"  - Tỷ lệ phát hiện đối kháng:  {clf['adversarial_detection_rate']}%")
            print(f"  --> TỶ LỆ LẨN TRÁNH THÀNH CÔNG: {clf['evasion_rate']}%")

        print("\n[Phân tích biến thiên đặc trưng tiêu biểu (Feature Shifts)]")
        shifts = results.get("feature_shifts", {})
        for name, data in list(shifts.items())[:8]:
            print(f"  * {name:<18}: Gốc = {data['orig_mean']:<10} | Đối kháng = {data['adv_mean']:<10} | Delta = {data['mean_delta']}")

        print("=" * 70 + "\n")
