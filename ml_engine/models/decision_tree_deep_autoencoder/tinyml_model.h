/**
 * ====================================================================
 * TINYML ON-DEVICE NETWORK ANOMALY DETECTION MODEL (AUTO-GENERATED)
 * Target: ESP32 / ESP32-S3 / ARM Cortex-M / Embedded Edge Gateways
 * ====================================================================
 * 
 * Features vector index:
 *   [0] arp.opcode
 *   [1] arp.hw.size
 *   [2] icmp.checksum
 *   [3] icmp.seq_le
 *   [4] icmp.transmit_timestamp
 *   [5] icmp.unused
 *   [6] http.file_data
 *   [7] http.content_length
 *   [8] http.request.uri.query
 *   [9] http.request.method
 *   [10] http.referer
 *   [11] http.request.full_uri
 *   [12] http.request.version
 *   [13] http.response
 *   [14] http.tls_port
 *   [15] tcp.ack
 *   [16] tcp.ack_raw
 *   [17] tcp.checksum
 *   [18] tcp.connection.fin
 *   [19] tcp.connection.rst
 *   [20] tcp.connection.syn
 *   [21] tcp.connection.synack
 *   [22] tcp.dstport
 *   [23] tcp.flags
 *   [24] tcp.flags.ack
 *   [25] tcp.len
 *   [26] tcp.options
 *   [27] tcp.payload
 *   [28] tcp.seq
 *   [29] tcp.srcport
 *   [30] udp.port
 *   [31] udp.stream
 *   [32] udp.time_delta
 *   [33] dns.qry.name
 *   [34] dns.qry.name.len
 *   [35] dns.qry.qu
 *   [36] dns.qry.type
 *   [37] dns.retransmission
 *   [38] dns.retransmit_request
 *   [39] dns.retransmit_request_in
 *   [40] mqtt.conack.flags
 *   [41] mqtt.conflag.cleansess
 *   [42] mqtt.conflags
 *   [43] mqtt.hdrflags
 *   [44] mqtt.len
 *   [45] mqtt.msg_decoded_as
 *   [46] mqtt.msg
 *   [47] mqtt.msgtype
 *   [48] mqtt.proto_len
 *   [49] mqtt.protoname
 *   [50] mqtt.topic
 *   [51] mqtt.topic_len
 *   [52] mqtt.ver
 *   [53] mbtcp.len
 *   [54] mbtcp.trans_id
 *   [55] mbtcp.unit_id
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

        if (features[50] <= -0.98409f) { // mqtt.topic <= -0.98
            *out_class_idx = 7; // Normal
            *out_anomaly_score = 1.0000f;
            return 1;
        } else {
            if (features[31] <= -0.24728f) { // udp.stream <= -0.25
                if (features[3] <= -0.25497f) { // icmp.seq_le <= -0.25
                    if (features[10] <= -0.76599f) { // http.referer <= -0.77
                        if (features[28] <= -0.13755f) { // tcp.seq <= -0.14
                            if (features[26] <= -0.27175f) { // tcp.options <= -0.27
                                if (features[15] <= -0.24679f) { // tcp.ack <= -0.25
                                    if (features[29] <= 0.01346f) { // tcp.srcport <= 0.01
                                        *out_class_idx = 14; // XSS
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 1; // DDoS_HTTP
                                        *out_anomaly_score = 0.8750f;
                                        return 1;
                                    }
                                } else {
                                    *out_class_idx = 1; // DDoS_HTTP
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            } else {
                                if (features[24] <= -0.31346f) { // tcp.flags.ack <= -0.31
                                    if (features[26] <= 1.96895f) { // tcp.options <= 1.97
                                        *out_class_idx = 1; // DDoS_HTTP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 14; // XSS
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[8] <= -0.27289f) { // http.request.uri.query <= -0.27
                                        *out_class_idx = 13; // Vulnerability_scanner
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        if (features[26] <= 0.54323f) { // tcp.options <= 0.54
                                            *out_class_idx = 13; // Vulnerability_scanner
                                            *out_anomaly_score = 0.7500f;
                                            return 1;
                                        } else {
                                            if (features[26] <= 1.60912f) { // tcp.options <= 1.61
                                                *out_class_idx = 14; // XSS
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[26] <= 2.00007f) { // tcp.options <= 2.00
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            *out_class_idx = 13; // Vulnerability_scanner
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        if (features[8] <= -0.27289f) { // http.request.uri.query <= -0.27
                            *out_class_idx = 11; // SQL_injection
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            if (features[11] <= -0.21580f) { // http.request.full_uri <= -0.22
                                if (features[6] <= -0.33373f) { // http.file_data <= -0.33
                                    *out_class_idx = 8; // Password
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[6] <= 1.35263f) { // http.file_data <= 1.35
                                        *out_class_idx = 12; // Uploading
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 8; // Password
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            } else {
                                if (features[26] <= -0.79108f) { // tcp.options <= -0.79
                                    if (features[27] <= 1.12160f) { // tcp.payload <= 1.12
                                        if (features[27] <= -0.51673f) { // tcp.payload <= -0.52
                                            if (features[15] <= -0.24679f) { // tcp.ack <= -0.25
                                                if (features[22] <= 1.45218f) { // tcp.dstport <= 1.45
                                                    if (features[28] <= -0.13763f) { // tcp.seq <= -0.14
                                                        *out_class_idx = 10; // Ransomware
                                                        *out_anomaly_score = 0.9091f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 10; // Ransomware
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 0; // Backdoor
                                                    *out_anomaly_score = 0.0000f;
                                                    return 0;
                                                }
                                            } else {
                                                *out_class_idx = 3; // DDoS_TCP
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[23] <= 1.08671f) { // tcp.flags <= 1.09
                                                if (features[12] <= -0.35719f) { // http.request.version <= -0.36
                                                    *out_class_idx = 6; // MITM
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[2] <= 0.29043f) { // icmp.checksum <= 0.29
                                                        if (features[29] <= 0.18341f) { // tcp.srcport <= 0.18
                                                            if (features[23] <= -0.34572f) { // tcp.flags <= -0.35
                                                                if (features[1] <= 8.84029f) { // arp.hw.size <= 8.84
                                                                    *out_class_idx = 9; // Port_Scanning
                                                                    *out_anomaly_score = 0.9286f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 9; // Port_Scanning
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 9; // Port_Scanning
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 5; // Fingerprinting
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 5; // Fingerprinting
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                *out_class_idx = 7; // Normal
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        *out_class_idx = 3; // DDoS_TCP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[26] <= 0.01417f) { // tcp.options <= 0.01
                                        if (features[16] <= 0.00155f) { // tcp.ack_raw <= 0.00
                                            *out_class_idx = 10; // Ransomware
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 0; // Backdoor
                                            *out_anomaly_score = 0.0000f;
                                            return 0;
                                        }
                                    } else {
                                        if (features[22] <= -0.66624f) { // tcp.dstport <= -0.67
                                            if (features[8] <= 1.85696f) { // http.request.uri.query <= 1.86
                                                if (features[11] <= 3.39426f) { // http.request.full_uri <= 3.39
                                                    if (features[24] <= -0.31346f) { // tcp.flags.ack <= -0.31
                                                        *out_class_idx = 6; // MITM
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 8; // Password
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 11; // SQL_injection
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[29] <= 1.33538f) { // tcp.srcport <= 1.34
                                                *out_class_idx = 10; // Ransomware
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 0; // Backdoor
                                                *out_anomaly_score = 0.0000f;
                                                return 0;
                                            }
                                        }
                                    }
                                }
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
