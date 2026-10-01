"""
Preprocessing and Feature Engineering Package
==============================================
Chỉ dẫn module:
- Cung cấp bộ tiền xử lý toàn diện cho tập dữ liệu Edge-IIoTset (EdgeTrafficPreprocessor).
- Cung cấp các module con theo tầng giao thức:
    * NetworkCorePreprocessor (ARP, ICMP)
    * TCPTransportPreprocessor (TCP)
    * UDPTransportPreprocessor (UDP)
    * HTTPApplicationPreprocessor (HTTP)
    * IoTProtocolsPreprocessor (DNS, MQTT, Modbus TCP)
- Cung cấp hàm nạp & xử lý dữ liệu cấp cao (load_and_preprocess_dataset, load_full_dataset).
- Cung cấp công cụ sinh tập dữ liệu mạng mô phỏng (Dataset Generator).
- Cung cấp bộ chuẩn hóa và trích xuất vector đặc trưng thời gian thực (TrafficFeaturePreprocessor).
"""

from .edge_iiotset_preprocessor import (
    EdgeTrafficPreprocessor,
    load_and_preprocess_dataset,
    load_full_dataset
)
from .dataset_generator import (
    generate_synthetic_dataset,
    save_synthetic_dataset
)
from .feature_preprocessor import (
    TrafficFeaturePreprocessor
)
from .modules import (
    BaseSubPreprocessor,
    NetworkCorePreprocessor,
    TCPTransportPreprocessor,
    UDPTransportPreprocessor,
    HTTPApplicationPreprocessor,
    IoTProtocolsPreprocessor,
    NETWORK_CORE_FEATURES,
    TCP_FEATURES,
    UDP_FEATURES,
    HTTP_FEATURES,
    IOT_FEATURES
)

__all__ = [
    "EdgeTrafficPreprocessor",
    "load_and_preprocess_dataset",
    "load_full_dataset",
    "generate_synthetic_dataset",
    "save_synthetic_dataset",
    "TrafficFeaturePreprocessor",
    "BaseSubPreprocessor",
    "NetworkCorePreprocessor",
    "TCPTransportPreprocessor",
    "UDPTransportPreprocessor",
    "HTTPApplicationPreprocessor",
    "IoTProtocolsPreprocessor",
    "NETWORK_CORE_FEATURES",
    "TCP_FEATURES",
    "UDP_FEATURES",
    "HTTP_FEATURES",
    "IOT_FEATURES"
]
