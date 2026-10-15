#include <esp32_packet_model.h>
#include <stdio.h>

int main() {
  char mode;
  while(scanf(" %c",&mode)==1) {
    if(mode!='V') return 2;
    float raw[ESP32_PACKET_FEATURE_COUNT],scaled[ESP32_PACKET_FEATURE_COUNT];
    float probabilities[ESP32_PACKET_CLASS_COUNT],score,sample;
    for(int i=0;i<ESP32_PACKET_FEATURE_COUNT;++i) if(scanf("%f",&raw[i])!=1) return 3;
    if(!esp32_preprocess(raw,scaled) || !esp32_predict_packet(raw,probabilities,&score,&sample)) return 4;
    printf("V %.10g %.10g",sample,score);
    for(int i=0;i<ESP32_PACKET_FEATURE_COUNT;++i) printf(" %.10g",scaled[i]);
    for(int i=0;i<ESP32_PACKET_CLASS_COUNT;++i) printf(" %.10g",probabilities[i]);
    printf("\n");
  }
  return 0;
}
