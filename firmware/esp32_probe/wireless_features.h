#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define WIRELESS_FEATURE_COUNT 14

extern const char* const WIRELESS_FEATURE_NAMES[14];

bool extractWirelessFeatures(
    const uint8_t* payload,
    uint16_t capturedLength,
    uint16_t originalLength,
    int8_t rssi,
    uint8_t channel,
    float out_features[14]
);
