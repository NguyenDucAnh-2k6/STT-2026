"""Generate an explicitly simulated Arduino inference demo from a parity-validated bundle."""
import argparse
import json
import shutil
from pathlib import Path

import numpy as np


def write_demo_vectors(vectors: np.ndarray, path: Path) -> None:
    def literal(value: float) -> str:
        text = format(float(value), ".9g")
        if "." not in text and "e" not in text.lower():
            text += ".0"
        return text + "f"
    values = ",\n".join("{" + ",".join(literal(value) for value in row) + "}" for row in vectors)
    path.write_text("// Prepared dataset vectors; simulated inputs, not live capture.\n#pragma once\n"
        f"#define DEMO_SAMPLE_COUNT {len(vectors)}\nstatic const float DEMO_INPUTS[][ESP32_PACKET_FEATURE_COUNT]={{\n{values}\n}};\n", encoding="utf-8")


def generate_demo_sketch(bundle: Path, output: Path, samples: int = 8) -> None:
    metadata = json.loads((bundle / "model_metadata.json").read_text(encoding="utf-8"))
    if not metadata.get("export_parity_validated"):
        raise ValueError("Validate native export parity before creating an Arduino demo")
    if output.exists():
        raise FileExistsError("Choose a new demo directory; existing sketches are preserved")
    vectors = np.load(bundle / "parity_vectors.npz")["raw"][:samples]
    if not len(vectors):
        raise ValueError("No prepared demonstration vectors")
    output.mkdir(parents=True)
    shutil.copy2(bundle / "esp32_packet_model.h", output / "demo_model.h")
    write_demo_vectors(vectors, output / "demo_vectors.h")
    sketch = """// Generated prepared-input inference demonstration. No network capture or training.
#include <Arduino.h>
#include "demo_model.h"
#include "demo_vectors.h"

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("SIMULATED INPUT DEMO — inference executes locally on ESP32");
  Serial.println(ESP32_PACKET_MODEL_NAME);
  Serial.println(ESP32_PACKET_PROFILE);
  for(int row=0;row<DEMO_SAMPLE_COUNT;++row) {
    float probabilities[ESP32_PACKET_CLASS_COUNT],score,sample;
    uint32_t started=micros();
    bool valid=esp32_predict_packet(DEMO_INPUTS[row],probabilities,&score,&sample);
    uint32_t elapsed=micros()-started;
    if(!valid) { Serial.println("Inference unavailable"); continue; }
    int winner=0;
    for(int c=1;c<ESP32_PACKET_CLASS_COUNT;++c) if(probabilities[c]>probabilities[winner]) winner=c;
    Serial.printf("Demo %d | Classifier=%s | anomaly_score=%.6f | gate=%s | latency_us=%lu\\n",
        row,ESP32_PACKET_LABELS[winner],score,score>=ESP32_PACKET_THRESHOLD ? "ANOMALY" : "NORMAL",(unsigned long)elapsed);
    for(int c=0;c<ESP32_PACKET_CLASS_COUNT;++c) {
      Serial.printf("  %-24s %6.2f%% ",ESP32_PACKET_LABELS[c],probabilities[c]*100);
      int bars=(int)(probabilities[c]*20);
      for(int i=0;i<bars;++i) Serial.print('#');
      Serial.println();
    }
  }
}

void loop() { delay(100); }
"""
    (output / f"{output.name}.ino").write_text(sketch, encoding="utf-8")
    (output / "demo_metadata.json").write_text(json.dumps({"artifact_id": metadata["artifact_id"],
        "profile": metadata["profile"], "samples": len(vectors), "input_kind": "prepared_dataset_vectors",
        "simulated_input": True, "hardware_validated": False}, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.samples <= 32:
        parser.error("--samples must be 1..32")
    generate_demo_sketch(args.bundle, args.output, args.samples)


if __name__ == "__main__":
    main()
