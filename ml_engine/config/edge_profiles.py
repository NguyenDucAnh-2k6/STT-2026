"""Deployment profiles preserve canonical names without changing the host schema."""

ESP32_PACKET_PROFILE = "esp32-l234-packet-v1"
ESP32_PACKET_FEATURES = [
    "arp.opcode", "arp.hw.size", "icmp.checksum", "tcp.ack_raw",
    "tcp.checksum", "tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.len", "tcp.srcport",
]

# Host / Gateway Deep Packet Inspection (Edge-IIoTset 56 features)
HOST_DPI_PROFILE = "edgeiiot-packet-v1"

# Wireless 802.11 Layer 2 WIDS profile (AWID3 Wi-Fi Frame Features)
AWID3_WIFI_PROFILE = "awid3-wifi-v1"
AWID3_WIFI_FEATURES = [
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
]

