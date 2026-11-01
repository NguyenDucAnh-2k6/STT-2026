#include "wireless_features.h"

const char* const WIRELESS_FEATURE_NAMES[14] = {
    "frame.len",
    "radiotap.channel.freq",
    "radiotap.dbm_antsignal",
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.fc.type_subtype",
    "wlan.fc.ds",
    "wlan.fc.frag",
    "wlan.fc.retry",
    "wlan.fc.pwrmgt",
    "wlan.fc.moredata",
    "wlan.fc.protected",
    "wlan.duration",
    "wlan.seq"
};

bool extractWirelessFeatures(
    const uint8_t* payload,
    uint16_t capturedLength,
    uint16_t originalLength,
    int8_t rssi,
    uint8_t channel,
    float out_features[14]
) {
  if (!payload || capturedLength < 24 || !out_features) return false;

  uint16_t fc = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
  uint8_t fc_type = (fc >> 2) & 0x03;
  uint8_t fc_subtype = (fc >> 4) & 0x0F;
  uint8_t fc_ts = (fc_type << 4) | fc_subtype;
  uint8_t fc_ds = ((fc >> 8) & 1) << 1 | ((fc >> 9) & 1);

  float freq = (channel == 14) ? 2484.0f : (2407.0f + channel * 5.0f);
  float duration = (float)((uint16_t)payload[2] | ((uint16_t)payload[3] << 8));
  float seq = (float)(((uint16_t)payload[22] | ((uint16_t)payload[23] << 8)) >> 4);

  out_features[0] = (float)originalLength;
  out_features[1] = freq;
  out_features[2] = (float)rssi;
  out_features[3] = (float)fc_type;
  out_features[4] = (float)fc_subtype;
  out_features[5] = (float)fc_ts;
  out_features[6] = (float)fc_ds;
  out_features[7] = (float)((fc >> 10) & 1);
  out_features[8] = (float)((fc >> 11) & 1);
  out_features[9] = (float)((fc >> 12) & 1);
  out_features[10] = (float)((fc >> 13) & 1);
  out_features[11] = (float)((fc >> 14) & 1); // wlan.fc.protected: 1 for WPA2, 0 for open
  out_features[12] = duration;
  out_features[13] = seq;

  return true;
}
