#pragma once
#include <stddef.h>
#include <stdint.h>
#ifndef ESP32_PACKET_MODEL_H
#include "esp32_packet_model.h"
#endif
static_assert(ESP32_PACKET_FEATURE_COUNT == 10 && ESP32_F_TCP_ACK_RAW == 3 && ESP32_F_TCP_SRCPORT == 9,
              "This radio parser requires the ten-feature packet profile; full 56-feature demos use prepared inputs");

enum class PacketFeatureStatus : uint8_t {
  Ok, Protected, Truncated, Fragmented, Unsupported, Malformed
};

struct PacketFeatures {
  uint32_t values[ESP32_PACKET_FEATURE_COUNT];
  PacketFeatureStatus status;
};

// Input is a driver-independent 802.11 frame, excluding FCS. No heap/I/O/state.
PacketFeatures extractPacketFeatures(const uint8_t* data, size_t capturedLength, size_t originalLength);
const char* packetFeatureStatusName(PacketFeatureStatus status);
