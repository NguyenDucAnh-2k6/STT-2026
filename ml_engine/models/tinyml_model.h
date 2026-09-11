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
    "Backdoor",
    "DDoS_HTTP",
    "DDoS_ICMP",
    "DDoS_TCP",
    "DDoS_UDP",
    "Fingerprinting",
    "MITM",
    "Normal",
    "Password",
    "Port_Scanning",
    "Ransomware",
    "SQL_injection",
    "Uploading",
    "Vulnerability_scanner",
    "XSS"
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

        if (features[17] <= -0.36175f) { // http.request.version <= -0.36
            if (features[15] <= -0.76495f) { // http.referer <= -0.76
                if (features[0] <= -1.01666f) { // frame.time <= -1.02
                    *out_class_idx = 1; // DDoS_HTTP
                    *out_anomaly_score = 1.0000f;
                    return 1;
                } else {
                    if (features[13] <= -0.17328f) { // http.request.uri.query <= -0.17
                        *out_class_idx = 13; // Vulnerability_scanner
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    } else {
                        *out_class_idx = 14; // XSS
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    }
                }
            } else {
                if (features[13] <= -0.17328f) { // http.request.uri.query <= -0.17
                    *out_class_idx = 11; // SQL_injection
                    *out_anomaly_score = 1.0000f;
                    return 1;
                } else {
                    if (features[0] <= 0.72300f) { // frame.time <= 0.72
                        if (features[0] <= -1.58659f) { // frame.time <= -1.59
                            *out_class_idx = 6; // MITM
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 8; // Password
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        if (features[34] <= -1.20825f) { // tcp.srcport <= -1.21
                            *out_class_idx = 6; // MITM
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 12; // Uploading
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    }
                }
            }
        } else {
            if (features[39] <= -0.95538f) { // dns.qry.name.len <= -0.96
                *out_class_idx = 7; // Normal
                *out_anomaly_score = 1.0000f;
                return 1;
            } else {
                if (features[27] <= -0.73991f) { // tcp.dstport <= -0.74
                    if (features[36] <= -0.25571f) { // udp.stream <= -0.26
                        if (features[8] <= -0.24512f) { // icmp.seq_le <= -0.25
                            if (features[31] <= -0.79790f) { // tcp.options <= -0.80
                                if (features[0] <= 0.64555f) { // frame.time <= 0.65
                                    if (features[0] <= -0.80654f) { // frame.time <= -0.81
                                        *out_class_idx = 10; // Ransomware
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 0; // Backdoor
                                        *out_anomaly_score = 0.0000f;
                                        return 0;
                                    }
                                } else {
                                    *out_class_idx = 10; // Ransomware
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            } else {
                                if (features[0] <= 0.17530f) { // frame.time <= 0.18
                                    *out_class_idx = 9; // Port_Scanning
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[7] <= 4.21529f) { // icmp.checksum <= 4.22
                                        *out_class_idx = 5; // Fingerprinting
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 2; // DDoS_ICMP
                                        *out_anomaly_score = 0.7500f;
                                        return 1;
                                    }
                                }
                            }
                        } else {
                            *out_class_idx = 2; // DDoS_ICMP
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        *out_class_idx = 4; // DDoS_UDP
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    }
                } else {
                    if (features[31] <= -0.79605f) { // tcp.options <= -0.80
                        if (features[0] <= -0.39533f) { // frame.time <= -0.40
                            if (features[32] <= -0.50758f) { // tcp.payload <= -0.51
                                *out_class_idx = 10; // Ransomware
                                *out_anomaly_score = 0.8750f;
                                return 1;
                            } else {
                                *out_class_idx = 9; // Port_Scanning
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            if (features[0] <= 0.13674f) { // frame.time <= 0.14
                                *out_class_idx = 3; // DDoS_TCP
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[0] <= 0.92027f) { // frame.time <= 0.92
                                    if (features[31] <= -0.79790f) { // tcp.options <= -0.80
                                        *out_class_idx = 0; // Backdoor
                                        *out_anomaly_score = 0.0000f;
                                        return 0;
                                    } else {
                                        *out_class_idx = 5; // Fingerprinting
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    *out_class_idx = 10; // Ransomware
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            }
                        }
                    } else {
                        if (features[16] <= -0.16598f) { // http.request.full_uri <= -0.17
                            if (features[31] <= 0.27715f) { // tcp.options <= 0.28
                                if (features[21] <= -0.39527f) { // tcp.ack_raw <= -0.40
                                    *out_class_idx = 10; // Ransomware
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 0; // Backdoor
                                    *out_anomaly_score = 0.0000f;
                                    return 0;
                                }
                            } else {
                                if (features[34] <= 0.30615f) { // tcp.srcport <= 0.31
                                    *out_class_idx = 10; // Ransomware
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 0; // Backdoor
                                    *out_anomaly_score = 0.0000f;
                                    return 0;
                                }
                            }
                        } else {
                            if (features[31] <= 0.10381f) { // tcp.options <= 0.10
                                *out_class_idx = 13; // Vulnerability_scanner
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[0] <= 0.54379f) { // frame.time <= 0.54
                                    if (features[17] <= 2.58651f) { // http.request.version <= 2.59
                                        *out_class_idx = 8; // Password
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 14; // XSS
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[13] <= 1.91598f) { // http.request.uri.query <= 1.92
                                        *out_class_idx = 12; // Uploading
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 11; // SQL_injection
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
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
