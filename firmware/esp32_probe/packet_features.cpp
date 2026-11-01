#include "packet_features.h"
#include <string.h>
#include <math.h>

static uint16_t be16(const uint8_t* p) {
  return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

const char* packetFeatureStatusName(PacketFeatureStatus status) {
  switch (status) {
    case PacketFeatureStatus::Ok: return "ok";
    case PacketFeatureStatus::Protected: return "encrypted_payload";
    case PacketFeatureStatus::Truncated: return "truncated_frame";
    case PacketFeatureStatus::Fragmented: return "fragmented_frame";
    case PacketFeatureStatus::Unsupported: return "unsupported_protocol";
    default: return "malformed_frame";
  }
}

PacketFeatures extractPacketFeatures(const uint8_t* data, size_t capturedLength, size_t originalLength) {
  PacketFeatures result = {};
  result.status = PacketFeatureStatus::Malformed;
  if (!data || capturedLength < 24 || (data[0] & 0x0f) != 8) return result;
  if (data[1] & 0x40) { result.status = PacketFeatureStatus::Protected; return result; }
  if (capturedLength < originalLength) { result.status = PacketFeatureStatus::Truncated; return result; }
  if ((data[1] & 4) || (data[22] & 15)) { result.status = PacketFeatureStatus::Fragmented; return result; }
  size_t headerLength = 24;
  if ((data[1] & 3) == 3) headerLength += 6;
  if (data[0] & 0x80) {
    if (capturedLength < headerLength + 2) return result;
    if (data[headerLength] & 0x80) { result.status = PacketFeatureStatus::Unsupported; return result; } // A-MSDU
    headerLength += 2;
    if (data[1] & 0x80) headerLength += 4;
  }
  if (capturedLength < headerLength + 8) return result;
  const uint8_t* llc = data + headerLength;
  const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0};
  if (memcmp(llc, snap, 6)) { result.status = PacketFeatureStatus::Unsupported; return result; }
  uint16_t etherType = be16(llc + 6);
  const uint8_t* network = llc + 8;
  size_t networkLength = capturedLength - headerLength - 8;
  if (etherType == 0x0806) {
    if (networkLength < 8) return result;
    size_t arpLength = 8 + 2 * ((size_t)network[4] + network[5]);
    if (networkLength < arpLength) return result;
    result.values[ESP32_F_ARP_OPCODE] = be16(network + 6);
    result.values[ESP32_F_ARP_HW_SIZE] = network[4];
  } else if (etherType == 0x0800) {
    if (networkLength < 20 || (network[0] >> 4) != 4) return result;
    size_t ipHeaderLength = (network[0] & 15) * 4;
    size_t ipLength = be16(network + 2);
    if (ipHeaderLength < 20 || ipLength < ipHeaderLength || networkLength < ipLength) return result;
    if (be16(network + 6) & 0x3fff) { result.status = PacketFeatureStatus::Fragmented; return result; }
    const uint8_t* transport = network + ipHeaderLength;
    size_t transportLength = ipLength - ipHeaderLength;
    if (network[9] == 6) {
      if (transportLength < 20) return result;
      size_t tcpHeaderLength = (transport[12] >> 4) * 4;
      if (tcpHeaderLength < 20 || tcpHeaderLength > transportLength) return result;
      uint16_t flags = ((uint16_t)(transport[12] & 1) << 8) | transport[13];
      result.values[ESP32_F_TCP_ACK_RAW] = be32(transport + 8);
      result.values[ESP32_F_TCP_CHECKSUM] = be16(transport + 16);
      result.values[ESP32_F_TCP_DSTPORT] = be16(transport + 2);
      result.values[ESP32_F_TCP_FLAGS] = flags;
      result.values[ESP32_F_TCP_FLAGS_ACK] = (flags & 0x10) ? 1.0f : 0.0f;
      result.values[ESP32_F_TCP_LEN] = transportLength - tcpHeaderLength;
      result.values[ESP32_F_TCP_SRCPORT] = be16(transport);
    } else if (network[9] == 1) {
      if (transportLength < 8) return result;
      if (transport[0] != 0 && transport[0] != 8 && transport[0] != 13 && transport[0] != 14) {
        result.status = PacketFeatureStatus::Unsupported;
        return result; // ICMP errors can contain quoted TCP fields in TShark.
      }
      result.values[ESP32_F_ICMP_CHECKSUM] = be16(transport + 2);
    } else {
      // This initial profile does not identify UDP-only traffic with zero vectors.
      result.status = PacketFeatureStatus::Unsupported;
      return result;
    }
  } else { result.status = PacketFeatureStatus::Unsupported; return result; }
  result.status = PacketFeatureStatus::Ok;
  return result;
}

float calculatePayloadEntropy(const uint8_t* payload, size_t length) {
  if (!payload || length == 0) return 0.0f;
  uint16_t counts[256] = {0};
  for (size_t i = 0; i < length; i++) {
    counts[payload[i]]++;
  }
  float entropy = 0.0f;
  float len_f = (float)length;
  for (int i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      float p = (float)counts[i] / len_f;
      entropy -= p * (logf(p) / 0.69314718056f); // log2(p) = ln(p) / ln(2)
    }
  }
  return entropy;
}

PacketFeatures extractRawIpFeatures(const uint8_t* ipData, size_t length, float* outEntropy) {
  PacketFeatures result = {};
  result.status = PacketFeatureStatus::Malformed;
  if (outEntropy) *outEntropy = 0.0f;
  if (!ipData || length < 20) return result;

  uint8_t ipVer = (ipData[0] >> 4) & 0x0F;
  if (ipVer != 4) { result.status = PacketFeatureStatus::Unsupported; return result; }

  size_t ipHeaderLength = (ipData[0] & 0x0F) * 4;
  size_t ipLength = be16(ipData + 2);
  if (ipHeaderLength < 20 || ipLength < ipHeaderLength || length < ipLength) return result;
  if (be16(ipData + 6) & 0x3FFF) { result.status = PacketFeatureStatus::Fragmented; return result; }

  const uint8_t* transport = ipData + ipHeaderLength;
  size_t transportLength = ipLength - ipHeaderLength;
  uint8_t protocol = ipData[9];

  if (protocol == 6) { // TCP
    if (transportLength < 20) return result;
    size_t tcpHeaderLength = (transport[12] >> 4) * 4;
    if (tcpHeaderLength < 20 || tcpHeaderLength > transportLength) return result;
    uint16_t flags = ((uint16_t)(transport[12] & 1) << 8) | transport[13];
    result.values[ESP32_F_TCP_ACK_RAW] = be32(transport + 8);
    result.values[ESP32_F_TCP_CHECKSUM] = be16(transport + 16);
    result.values[ESP32_F_TCP_DSTPORT] = be16(transport + 2);
    result.values[ESP32_F_TCP_FLAGS] = flags;
    result.values[ESP32_F_TCP_FLAGS_ACK] = (flags & 0x10) ? 1.0f : 0.0f;
    size_t payloadLen = transportLength - tcpHeaderLength;
    result.values[ESP32_F_TCP_LEN] = (uint32_t)payloadLen;
    result.values[ESP32_F_TCP_SRCPORT] = be16(transport);

    if (outEntropy && payloadLen > 0) {
      *outEntropy = calculatePayloadEntropy(transport + tcpHeaderLength, payloadLen);
    }
  } else if (protocol == 1) { // ICMP
    if (transportLength < 8) return result;
    result.values[ESP32_F_ICMP_CHECKSUM] = be16(transport + 2);
  } else if (protocol == 17) { // UDP
    if (transportLength < 8) return result;
    size_t udpPayloadLen = (transportLength > 8) ? (transportLength - 8) : 0;
    if (outEntropy && udpPayloadLen > 0) {
      *outEntropy = calculatePayloadEntropy(transport + 8, udpPayloadLen);
    }
  } else {
    result.status = PacketFeatureStatus::Unsupported;
    return result;
  }

  result.status = PacketFeatureStatus::Ok;
  return result;
}

