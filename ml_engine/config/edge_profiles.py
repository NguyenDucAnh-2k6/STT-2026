"""Deployment profiles preserve canonical names without changing the host schema."""

ESP32_PACKET_PROFILE = "esp32-l234-packet-v1"
ESP32_PACKET_FEATURES = [
    "arp.opcode", "arp.hw.size", "icmp.checksum", "tcp.ack_raw",
    "tcp.checksum", "tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.len", "tcp.srcport",
]
