# Đặc Tả Giao Thức MQTT (MQTT API Specification)

Hệ thống sử dụng giao thức **MQTT 3.1.1** để trao đổi dữ liệu phân tán giữa các thiết bị biên (ESP32 probes), bộ máy suy luận học máy (ML Engine), và bảng điều khiển (SOC Dashboard).

---

## 1. Bảng Danh Mục Topics (Topic Hierarchy)

| Topic | Publisher | Subscriber | QoS | Mục Đích |
|---|---|---|---|---|
| `edge/telemetry/traffic` | ESP32 / Simulator | ML Engine, Dashboard | 0 | Truyền vector đặc trưng lưu lượng mạng định kỳ theo cửa sổ lấy mẫu |
| `edge/telemetry/prediction` | ML Engine | Dashboard | 0 | Truyền kết quả suy luận bất thường (anomaly score, threat type) |
| `edge/alerts/high_priority` | ML Engine / ESP32 | Dashboard, Alert System | 1 | Phát cảnh báo khẩn cấp khi phát hiện dấu hiệu tấn công mạng |
| `edge/nodes/status` | ESP32 / Simulator | Dashboard | 1 | Báo cáo trạng thái trực tuyến (online / offline) của các probe |
| `edge/simulator/control` | Dashboard Web UI | Simulator | 0 | Điều khiển kịch bản tấn công thử nghiệm từ xa |

---

## 2. Chi Tiết Cấu Trúc Payload JSON

### 2.1. `edge/telemetry/traffic`
Dữ liệu đặc trưng trích xuất từ ESP32 sau mỗi chu kỳ lấy mẫu (mặc định 2 giây):

```json
{
  "device_id": "ESP32-EdgeProbe-01",
  "timestamp": 1714567890123,
  "channel": 1,
  "packet_rate": 142.5,
  "byte_rate": 78400.0,
  "avg_packet_size": 550.2,
  "syn_ratio": 0.045,
  "ack_ratio": 0.782,
  "udp_ratio": 0.185,
  "icmp_ratio": 0.005,
  "unique_dst_ports": 12,
  "tcp_count": 210,
  "udp_count": 48,
  "icmp_count": 2,
  "edge_flag": false,
  "edge_prediction": "Normal",
  "edge_anomaly_score": 0.02,
  "edge_model": "TinyML-DecisionTree-v1"
}
```

### 2.2. `edge/telemetry/prediction`
Dữ liệu giàu đặc trưng sau khi ML Engine (Isolation Forest + Decision Classifier) phân tích:

```json
{
  "device_id": "ESP32-EdgeProbe-01",
  "timestamp": 1714567890123,
  "is_anomaly": true,
  "anomaly_score": 0.8924,
  "severity": "CRITICAL",
  "threat_type": "SYN_Flood",
  "confidence": 1.0,
  "latency_ms": 1.42,
  "raw_telemetry": { ... }
}
```

### 2.3. `edge/alerts/high_priority`
Cảnh báo phát động khi `is_anomaly == true` hoặc `anomaly_score > threshold`:

```json
{
  "id": "alert_1714567890123_1",
  "timestamp": 1714567890123,
  "device_id": "ESP32-EdgeProbe-01",
  "threat_type": "SYN_Flood",
  "severity": "CRITICAL",
  "anomaly_score": 0.8924,
  "details": "Packet Rate: 2450.0 pkts/s | SYN: 0.96"
}
```

### 2.4. `edge/simulator/control`
Lệnh kích hoạt kịch bản tấn công từ Web UI:

```json
{
  "command": "INJECT_MODE",
  "mode": "SYN_FLOOD"
}
```
*Các giá trị `mode` được hỗ trợ*: `"NORMAL"`, `"SYN_FLOOD"`, `"PORT_SCAN"`, `"VOLUMETRIC_DDOS"`, `"DATA_EXFILTRATION"`.
