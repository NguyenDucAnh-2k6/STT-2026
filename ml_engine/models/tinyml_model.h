/**
 * ====================================================================
 * TINYML ON-DEVICE NETWORK ANOMALY DETECTION MODEL (AUTO-GENERATED)
 * Target: ESP32 / ESP32-S3 / ARM Cortex-M / Embedded Edge Gateways
 * ====================================================================
 * 
 * Features vector index:
 *   [0] frame.time
 *   [1] ip.src_host
 *   [2] ip.dst_host
 *   [3] arp.dst.proto_ipv4
 *   [4] arp.opcode
 *   [5] arp.hw.size
 *   [6] arp.src.proto_ipv4
 *   [7] icmp.checksum
 *   [8] icmp.seq_le
 *   [9] icmp.transmit_timestamp
 *   [10] icmp.unused
 *   [11] http.file_data
 *   [12] http.content_length
 *   [13] http.request.uri.query
 *   [14] http.request.method
 *   [15] http.referer
 *   [16] http.request.full_uri
 *   [17] http.request.version
 *   [18] http.response
 *   [19] http.tls_port
 *   [20] tcp.ack
 *   [21] tcp.ack_raw
 *   [22] tcp.checksum
 *   [23] tcp.connection.fin
 *   [24] tcp.connection.rst
 *   [25] tcp.connection.syn
 *   [26] tcp.connection.synack
 *   [27] tcp.dstport
 *   [28] tcp.flags
 *   [29] tcp.flags.ack
 *   [30] tcp.len
 *   [31] tcp.options
 *   [32] tcp.payload
 *   [33] tcp.seq
 *   [34] tcp.srcport
 *   [35] udp.port
 *   [36] udp.stream
 *   [37] udp.time_delta
 *   [38] dns.qry.name
 *   [39] dns.qry.name.len
 *   [40] dns.qry.qu
 *   [41] dns.qry.type
 *   [42] dns.retransmission
 *   [43] dns.retransmit_request
 *   [44] dns.retransmit_request_in
 *   [45] mqtt.conack.flags
 *   [46] mqtt.conflag.cleansess
 *   [47] mqtt.conflags
 *   [48] mqtt.hdrflags
 *   [49] mqtt.len
 *   [50] mqtt.msg_decoded_as
 *   [51] mqtt.msg
 *   [52] mqtt.msgtype
 *   [53] mqtt.proto_len
 *   [54] mqtt.protoname
 *   [55] mqtt.topic
 *   [56] mqtt.topic_len
 *   [57] mqtt.ver
 *   [58] mbtcp.len
 *   [59] mbtcp.trans_id
 *   [60] mbtcp.unit_id
 */

#ifndef TINYML_MODEL_H
#define TINYML_MODEL_H

#ifdef __cplusplus
extern "C" {
#endif

// Danh sach ten nhan tan cong
static const char* TINYML_LABEL_NAMES[] = {
    "Normal",
    "DDoS_UDP",
    "DDoS_ICMP",
    "Ransomware",
    "DDoS_HTTP",
    "SQL_injection",
    "Uploading",
    "DDoS_TCP",
    "Backdoor",
    "Vulnerability_scanner",
    "Port_Scanning",
    "XSS",
    "Password",
    "MITM",
    "Fingerprinting"
};

/**
 * @brief Chay suy luan phat hien bat thuong luu luong truc tiep tren chip ESP32
 * @param features Mang float 8 phan tu chua dac trung luu luong
 * @param out_class_idx Con tro nhan chi so lop tan cong (0 -> 4)
 * @param out_anomaly_score Con tro nhan diem nguy hiem [0.0 -> 1.0]
 * @return int 0: Normal, 1: Anomaly (Phat hien tan cong)
 */
static inline int tinyml_predict_anomaly(
    const float* features,
    int* out_class_idx,
    float* out_anomaly_score
) {
    if (!features || !out_class_idx || !out_anomaly_score) return -1;

        if (features[17] <= -0.35498f) { // http.request.version <= -0.35
            if (features[15] <= -0.76523f) { // http.referer <= -0.77
                if (features[0] <= -1.04060f) { // frame.time <= -1.04
                    *out_class_idx = 1; // DDoS_UDP
                    *out_anomaly_score = 1.0000f;
                    return 1;
                } else {
                    if (features[13] <= -0.27756f) { // http.request.uri.query <= -0.28
                        *out_class_idx = 13; // MITM
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    } else {
                        *out_class_idx = 14; // Fingerprinting
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    }
                }
            } else {
                if (features[0] <= 0.86788f) { // frame.time <= 0.87
                    if (features[13] <= -0.27756f) { // http.request.uri.query <= -0.28
                        *out_class_idx = 11; // XSS
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    } else {
                        if (features[3] <= 1.31968f) { // arp.dst.proto_ipv4 <= 1.32
                            *out_class_idx = 8; // Backdoor
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 6; // Uploading
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    }
                } else {
                    if (features[0] <= 1.43035f) { // frame.time <= 1.43
                        *out_class_idx = 12; // Password
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    } else {
                        *out_class_idx = 6; // Uploading
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    }
                }
            }
        } else {
            if (features[39] <= -0.95591f) { // dns.qry.name.len <= -0.96
                *out_class_idx = 7; // DDoS_TCP
                *out_anomaly_score = 1.0000f;
                return 1;
            } else {
                if (features[28] <= -1.28804f) { // tcp.flags <= -1.29
                    if (features[7] <= -0.20720f) { // icmp.checksum <= -0.21
                        if (features[36] <= -0.24860f) { // udp.stream <= -0.25
                            if (features[32] <= -0.51495f) { // tcp.payload <= -0.51
                                if (features[0] <= 0.65492f) { // frame.time <= 0.65
                                    *out_class_idx = 0; // Normal
                                    *out_anomaly_score = 0.3333f;
                                    return 0;
                                } else {
                                    *out_class_idx = 10; // Port_Scanning
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            } else {
                                *out_class_idx = 9; // Vulnerability_scanner
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            *out_class_idx = 4; // DDoS_HTTP
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        if (features[8] <= -0.25246f) { // icmp.seq_le <= -0.25
                            *out_class_idx = 5; // SQL_injection
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 2; // DDoS_ICMP
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    }
                } else {
                    if (features[31] <= -0.79052f) { // tcp.options <= -0.79
                        if (features[0] <= -0.42489f) { // frame.time <= -0.42
                            if (features[32] <= -0.51495f) { // tcp.payload <= -0.51
                                *out_class_idx = 0; // Normal
                                *out_anomaly_score = 0.5000f;
                                return 0;
                            } else {
                                *out_class_idx = 9; // Vulnerability_scanner
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            if (features[20] <= -0.22954f) { // tcp.ack <= -0.23
                                if (features[27] <= 1.46450f) { // tcp.dstport <= 1.46
                                    *out_class_idx = 10; // Port_Scanning
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[21] <= -0.55302f) { // tcp.ack_raw <= -0.55
                                        *out_class_idx = 5; // SQL_injection
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 0; // Normal
                                        *out_anomaly_score = 0.0000f;
                                        return 0;
                                    }
                                }
                            } else {
                                *out_class_idx = 3; // Ransomware
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        }
                    } else {
                        if (features[27] <= -0.66837f) { // tcp.dstport <= -0.67
                            if (features[31] <= 0.10695f) { // tcp.options <= 0.11
                                *out_class_idx = 13; // MITM
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[0] <= 0.53687f) { // frame.time <= 0.54
                                    if (features[16] <= 5.73414f) { // http.request.full_uri <= 5.73
                                        *out_class_idx = 8; // Backdoor
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 14; // Fingerprinting
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[0] <= 0.87829f) { // frame.time <= 0.88
                                        *out_class_idx = 11; // XSS
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 12; // Password
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            }
                        } else {
                            if (features[31] <= 0.29299f) { // tcp.options <= 0.29
                                if (features[0] <= -0.89478f) { // frame.time <= -0.89
                                    *out_class_idx = 10; // Port_Scanning
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 0; // Normal
                                    *out_anomaly_score = 0.0000f;
                                    return 0;
                                }
                            } else {
                                if (features[34] <= 0.33695f) { // tcp.srcport <= 0.34
                                    *out_class_idx = 10; // Port_Scanning
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 0; // Normal
                                    *out_anomaly_score = 0.0000f;
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
}

/**
 * @brief Lay ten chuoi mo ta tan cong tu chi so lop
 */
static inline const char* tinyml_get_threat_name(int class_idx) {
    if (class_idx >= 0 && class_idx < 15) {
        return TINYML_LABEL_NAMES[class_idx];
    }
    return "Unknown";
}

#ifdef __cplusplus
}
#endif

#endif // TINYML_MODEL_H
