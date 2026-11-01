"""
Preprocessing Protocol Modules Package
======================================
Xuất các module tiền xử lý con theo tầng giao thức:
- NetworkCorePreprocessor: ARP & ICMP
- TCPTransportPreprocessor: TCP
- UDPTransportPreprocessor: UDP
- HTTPApplicationPreprocessor: HTTP
- IoTProtocolsPreprocessor: DNS, MQTT, Modbus TCP
"""

from .base import BaseSubPreprocessor
from .network_core import NetworkCorePreprocessor, NETWORK_CORE_FEATURES
from .tcp_transport import TCPTransportPreprocessor, TCP_FEATURES
from .udp_transport import UDPTransportPreprocessor, UDP_FEATURES
from .http_application import HTTPApplicationPreprocessor, HTTP_FEATURES
from .iot_protocols import IoTProtocolsPreprocessor, IOT_FEATURES
from .payload_entropy import (
    PayloadEntropyPreprocessor,
    PAYLOAD_ENTROPY_FEATURES,
    calculate_byte_entropy,
    extract_payload_statistics,
    parse_hex_to_bytes
)
from .flow_dynamics import (
    FlowDynamicsPreprocessor,
    FLOW_DYNAMICS_FEATURES,
    compute_biflow_features_from_packets,
    partition_into_subflows
)
from .tls_handshake import (
    TLSHandshakePreprocessor,
    TLS_HANDSHAKE_FEATURES,
    parse_tls_client_hello
)
from .wifi_wireless import (
    WifiWirelessPreprocessor,
    WIFI_CORE_FEATURES,
    WIFI_WINDOW_EXTENDED_FEATURES,
    ALL_WIFI_FEATURES,
    parse_80211_frame_header
)

__all__ = [
    "BaseSubPreprocessor",
    "NetworkCorePreprocessor",
    "TCPTransportPreprocessor",
    "UDPTransportPreprocessor",
    "HTTPApplicationPreprocessor",
    "IoTProtocolsPreprocessor",
    "PayloadEntropyPreprocessor",
    "FlowDynamicsPreprocessor",
    "TLSHandshakePreprocessor",
    "WifiWirelessPreprocessor",
    "NETWORK_CORE_FEATURES",
    "TCP_FEATURES",
    "UDP_FEATURES",
    "HTTP_FEATURES",
    "IOT_FEATURES",
    "PAYLOAD_ENTROPY_FEATURES",
    "FLOW_DYNAMICS_FEATURES",
    "TLS_HANDSHAKE_FEATURES",
    "WIFI_CORE_FEATURES",
    "WIFI_WINDOW_EXTENDED_FEATURES",
    "ALL_WIFI_FEATURES",
    "calculate_byte_entropy",
    "extract_payload_statistics",
    "parse_hex_to_bytes",
    "compute_biflow_features_from_packets",
    "partition_into_subflows",
    "parse_tls_client_hello",
    "parse_80211_frame_header"
]

