#include <esp32_packet_model.h>
#include "packet_features.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <stdlib.h>

int main() {
  std::cout << std::setprecision(10);
  char mode;
  while (std::cin >> mode) {
    float raw[ESP32_PACKET_FEATURE_COUNT];
    if (mode == 'F') {
      std::string hex;
      size_t originalLength;
      std::cin >> originalLength >> hex;
      std::vector<uint8_t> bytes;
      for (size_t i=0;i<hex.size();i+=2) bytes.push_back((uint8_t)strtoul(hex.substr(i,2).c_str(),nullptr,16));
      PacketFeatures packet=extractPacketFeatures(bytes.data(),bytes.size(),originalLength);
      std::cout << "F " << packetFeatureStatusName(packet.status);
      for (uint32_t value:packet.values) std::cout << ' ' << value;
      std::cout << '\n';
      continue;
    }
    for (float& value:raw) if (!(std::cin>>value)) return 2;
    float scaled[ESP32_PACKET_FEATURE_COUNT], probabilities[ESP32_PACKET_CLASS_COUNT], score, sample;
    if (!esp32_preprocess(raw,scaled) || !esp32_predict_packet(raw,probabilities,&score,&sample)) return 3;
    std::cout << "V " << sample << ' ' << score;
    for (float value:scaled) std::cout << ' ' << value;
    for (float value:probabilities) std::cout << ' ' << value;
    std::cout << '\n';
  }
  return 0;
}
