// Generated prepared-input inference demonstration. No network capture or training.
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
    Serial.printf("Demo %d | Classifier=%s | anomaly_score=%.6f | gate=%s | latency_us=%lu\n",
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
