"""Compile the exported packet model; require native parity before firmware deployment."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import numpy as np

from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES


def validate_export(bundle: Path, compiler: Path, root: Path) -> dict:
    metadata_path = bundle / "model_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    packet_profile = metadata.get("features") == ESP32_PACKET_FEATURES
    count = len(metadata["features"])
    temporary = root / ".esp32_validation_env" / "native"
    temporary.mkdir(parents=True, exist_ok=True)
    executable = temporary / ("esp32_packet_parity.exe" if packet_profile else f"esp32_model_{bundle.name}.exe")
    command = [str(compiler), "c++", "-std=c++11", "-O2", "-include", str(bundle / "esp32_packet_model.h"),
        "-I", str(bundle), "-I", str(root / "firmware/esp32_probe"),
        str(root / "tests" / ("esp32_packet_native.cpp" if packet_profile else "esp32_model_native.cpp"))]
    if packet_profile:
        command.append(str(root / "firmware/esp32_probe/packet_features.cpp"))
    else:
        command.append("-nostdlib++")
    command += ["-o", str(executable)]
    environment = os.environ.copy()
    environment["ZIG_GLOBAL_CACHE_DIR"] = str(temporary / "global-cache")
    environment["ZIG_LOCAL_CACHE_DIR"] = str(temporary / "cache")
    compilation = subprocess.run(command, timeout=180, env=environment, cwd=temporary, capture_output=True)
    if compilation.returncode:
        (temporary / "compile_error.txt").write_bytes(compilation.stderr[-20000:])
        raise RuntimeError("Native compile failed; see .esp32_validation_env/native/compile_error.txt")
    vectors = np.load(bundle / "parity_vectors.npz")
    rows = ["V " + " ".join(format(float(value), ".9g") for value in row) for row in vectors["raw"]]
    output = subprocess.run([str(executable)], input="\n".join(rows) + "\n", text=True, capture_output=True, check=True, timeout=30)
    actual = np.array([[float(value) for value in line.split()[1:]] for line in output.stdout.splitlines()])
    expected_probabilities = np.zeros((len(rows), actual.shape[1] - 2 - count))
    expected_probabilities[:, vectors["classes"].astype(int)] = vectors["probabilities"]
    np.testing.assert_allclose(actual[:, 2:2+count], vectors["scaled"], rtol=2e-6, atol=2e-6)
    np.testing.assert_allclose(actual[:, 2+count:], expected_probabilities, rtol=2e-6, atol=2e-6)
    np.testing.assert_allclose(actual[:, 0], vectors["score_samples"], rtol=2e-6, atol=2e-6)
    if "normalized_scores" in vectors:
        expected_score = vectors["normalized_scores"]
    else:
        distance = (metadata["isolation_score_max"] - vectors["score_samples"]) / max(metadata["isolation_score_max"] - metadata["isolation_score_min"], 1e-6)
        expected_score = 1 / (1 + np.exp(-4 * (distance - .5)))
    np.testing.assert_allclose(actual[:, 1], expected_score, rtol=2e-6, atol=2e-6)
    np.testing.assert_array_equal(actual[:, 1] >= metadata["anomaly_threshold"], expected_score >= metadata["anomaly_threshold"])
    np.testing.assert_array_equal(actual[:, 2+count:].argmax(axis=1), expected_probabilities.argmax(axis=1))
    report = {"vectors": len(rows), "features": count, "rtol": 2e-6, "atol": 2e-6,
        "maximum_scaling_error": float(np.max(np.abs(actual[:, 2:2+count] - vectors["scaled"]))),
        "maximum_anomaly_score_error": float(np.max(np.abs(actual[:, 1] - expected_score))),
        "header_sha256": hashlib.sha256((bundle / "esp32_packet_model.h").read_bytes()).hexdigest(),
        "native_executable": str(executable.relative_to(root)), "hardware_validated": False}
    (bundle / "export_parity.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    metadata.update(export_parity_validated=True, export_header_sha256=report["header_sha256"])
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--deploy", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    validate_export(args.bundle.resolve(), args.compiler.resolve(), root)
    if args.deploy:
        metadata = json.loads((args.bundle / "model_metadata.json").read_text(encoding="utf-8"))
        if metadata["features"] != ESP32_PACKET_FEATURES:
            raise ValueError("The radio firmware cannot extract this feature profile; full-vector demos are not deployed as live packet models")
        shutil.copy2(args.bundle / "esp32_packet_model.h", root / "firmware/esp32_probe/esp32_packet_model.h")


if __name__ == "__main__":
    main()
