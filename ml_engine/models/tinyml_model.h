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

        if (features[31] <= -0.28183f) { // udp.stream <= -0.28
            if (features[3] <= -0.25925f) { // icmp.seq_le <= -0.26
                if (features[7] <= -0.14850f) { // http.content_length <= -0.15
                    if (features[27] <= 2.14057f) { // tcp.payload <= 2.14
                        if (features[22] <= -0.66718f) { // tcp.dstport <= -0.67
                            if (features[15] <= 1.37340f) { // tcp.ack <= 1.37
                                if (features[29] <= 1.51053f) { // tcp.srcport <= 1.51
                                    if (features[29] <= 0.51294f) { // tcp.srcport <= 0.51
                                        if (features[29] <= 0.44648f) { // tcp.srcport <= 0.45
                                            if (features[29] <= -0.23746f) { // tcp.srcport <= -0.24
                                                if (features[2] <= -0.07487f) { // icmp.checksum <= -0.07
                                                    if (features[30] <= 7.18493f) { // udp.port <= 7.18
                                                        if (features[0] <= 4.12989f) { // arp.opcode <= 4.13
                                                            if (features[16] <= -0.45464f) { // tcp.ack_raw <= -0.45
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 0.6461f;
                                                                return 1;
                                                            } else {
                                                                if (features[15] <= -0.37972f) { // tcp.ack <= -0.38
                                                                    *out_class_idx = 9; // Port_Scanning
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 3; // DDoS_TCP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[0] <= 12.54794f) { // arp.opcode <= 12.55
                                                                *out_class_idx = 9; // Port_Scanning
                                                                *out_anomaly_score = 0.7826f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 9; // Port_Scanning
                                                                *out_anomaly_score = 0.7917f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        *out_class_idx = 6; // MITM
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    if (features[2] <= 4.35677f) { // icmp.checksum <= 4.36
                                                        *out_class_idx = 5; // Fingerprinting
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 5; // Fingerprinting
                                                        *out_anomaly_score = 0.8333f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                if (features[28] <= -0.28183f) { // tcp.seq <= -0.28
                                                    if (features[17] <= 1.66148f) { // tcp.checksum <= 1.66
                                                        if (features[28] <= -0.28242f) { // tcp.seq <= -0.28
                                                            *out_class_idx = 14; // XSS
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[15] <= -0.37839f) { // tcp.ack <= -0.38
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 0.7500f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[28] <= -0.28179f) { // tcp.seq <= -0.28
                                                if (features[25] <= 0.04150f) { // tcp.len <= 0.04
                                                    if (features[24] <= -0.29529f) { // tcp.flags.ack <= -0.30
                                                        if (features[29] <= 0.46151f) { // tcp.srcport <= 0.46
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.8000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[17] <= 0.54240f) { // tcp.checksum <= 0.54
                                                            if (features[17] <= 0.40187f) { // tcp.checksum <= 0.40
                                                                if (features[17] <= -0.06401f) { // tcp.checksum <= -0.06
                                                                    if (features[29] <= 0.49544f) { // tcp.srcport <= 0.50
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= 0.11395f) { // tcp.checksum <= 0.11
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        if (features[29] <= 0.96858f) { // tcp.srcport <= 0.97
                                            if (features[15] <= -0.37671f) { // tcp.ack <= -0.38
                                                if (features[15] <= -0.37881f) { // tcp.ack <= -0.38
                                                    if (features[25] <= 0.11683f) { // tcp.len <= 0.12
                                                        if (features[25] <= -0.09870f) { // tcp.len <= -0.10
                                                            if (features[23] <= -0.29538f) { // tcp.flags <= -0.30
                                                                if (features[29] <= 0.79101f) { // tcp.srcport <= 0.79
                                                                    if (features[29] <= 0.68808f) { // tcp.srcport <= 0.69
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8103f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.9667f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[29] <= 0.89489f) { // tcp.srcport <= 0.89
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.8200f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7407f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[28] <= -0.28288f) { // tcp.seq <= -0.28
                                                                    if (features[23] <= 0.40234f) { // tcp.flags <= 0.40
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.8068f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[29] <= 0.72074f) { // tcp.srcport <= 0.72
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[25] <= -0.05209f) { // tcp.len <= -0.05
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                if (features[25] <= 0.08401f) { // tcp.len <= 0.08
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if (features[25] <= 0.13323f) { // tcp.len <= 0.13
                                                            if (features[17] <= 0.34687f) { // tcp.checksum <= 0.35
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 11; // SQL_injection
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[28] <= -0.27911f) { // tcp.seq <= -0.28
                                                        *out_class_idx = 11; // SQL_injection
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[15] <= -0.37280f) { // tcp.ack <= -0.37
                                                if (features[15] <= -0.37992f) { // tcp.ack <= -0.38
                                                    if (features[28] <= -0.28263f) { // tcp.seq <= -0.28
                                                        if (features[29] <= 1.47923f) { // tcp.srcport <= 1.48
                                                            if (features[29] <= 1.18139f) { // tcp.srcport <= 1.18
                                                                if (features[29] <= 1.07681f) { // tcp.srcport <= 1.08
                                                                    if (features[29] <= 1.05956f) { // tcp.srcport <= 1.06
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7647f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= 1.55286f) { // tcp.checksum <= 1.55
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.6842f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[29] <= 1.36746f) { // tcp.srcport <= 1.37
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[29] <= 1.39083f) { // tcp.srcport <= 1.39
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[29] <= 1.50646f) { // tcp.srcport <= 1.51
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        if (features[23] <= -0.29538f) { // tcp.flags <= -0.30
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.8000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[28] <= -0.28170f) { // tcp.seq <= -0.28
                                                        if (features[29] <= 1.48699f) { // tcp.srcport <= 1.49
                                                            if (features[17] <= 1.43528f) { // tcp.checksum <= 1.44
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[29] <= 1.21495f) { // tcp.srcport <= 1.21
                                                            *out_class_idx = 13; // Vulnerability_scanner
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.9000f;
                                                            return 1;
                                                        }
                                                    }
                                                }
                                            } else {
                                                *out_class_idx = 13; // Vulnerability_scanner
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    }
                                } else {
                                    if (features[15] <= -0.37869f) { // tcp.ack <= -0.38
                                        if (features[15] <= -0.37967f) { // tcp.ack <= -0.38
                                            if (features[28] <= -0.28184f) { // tcp.seq <= -0.28
                                                if (features[25] <= -0.02413f) { // tcp.len <= -0.02
                                                    if (features[20] <= 1.12293f) { // tcp.connection.syn <= 1.12
                                                        if (features[25] <= -0.03196f) { // tcp.len <= -0.03
                                                            if (features[23] <= 0.61702f) { // tcp.flags <= 0.62
                                                                if (features[28] <= -0.28288f) { // tcp.seq <= -0.28
                                                                    if (features[17] <= 0.39132f) { // tcp.checksum <= 0.39
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8056f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.9062f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 5; // Fingerprinting
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 14; // XSS
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[29] <= 1.51981f) { // tcp.srcport <= 1.52
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 0.8000f;
                                                            return 1;
                                                        } else {
                                                            if (features[17] <= 1.55926f) { // tcp.checksum <= 1.56
                                                                if (features[17] <= -0.84715f) { // tcp.checksum <= -0.85
                                                                    if (features[29] <= 1.54712f) { // tcp.srcport <= 1.55
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[29] <= 1.58068f) { // tcp.srcport <= 1.58
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.7250f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.8750f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[17] <= -0.76958f) { // tcp.checksum <= -0.77
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 0.7500f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[15] <= -0.37917f) { // tcp.ack <= -0.38
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
                                        if (features[15] <= -0.37831f) { // tcp.ack <= -0.38
                                            *out_class_idx = 14; // XSS
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 8; // Password
                                            *out_anomaly_score = 0.8000f;
                                            return 1;
                                        }
                                    }
                                }
                            } else {
                                *out_class_idx = 9; // Port_Scanning
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            if (features[29] <= -0.86240f) { // tcp.srcport <= -0.86
                                if (features[22] <= -0.26761f) { // tcp.dstport <= -0.27
                                    if (features[15] <= -0.37972f) { // tcp.ack <= -0.38
                                        *out_class_idx = 9; // Port_Scanning
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 3; // DDoS_TCP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[19] <= 1.39729f) { // tcp.connection.rst <= 1.40
                                        if (features[15] <= -0.37904f) { // tcp.ack <= -0.38
                                            if (features[22] <= 1.69051f) { // tcp.dstport <= 1.69
                                                if (features[22] <= 0.70728f) { // tcp.dstport <= 0.71
                                                    if (features[22] <= 0.62636f) { // tcp.dstport <= 0.63
                                                        if (features[25] <= -0.04650f) { // tcp.len <= -0.05
                                                            if (features[28] <= -0.28160f) { // tcp.seq <= -0.28
                                                                if (features[15] <= -0.37957f) { // tcp.ack <= -0.38
                                                                    if (features[17] <= -0.03381f) { // tcp.checksum <= -0.03
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[15] <= -0.37937f) { // tcp.ack <= -0.38
                                                            if (features[15] <= -0.37974f) { // tcp.ack <= -0.38
                                                                if (features[22] <= 0.67538f) { // tcp.dstport <= 0.68
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.9000f;
                                                                    return 1;
                                                                }
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
                                                    }
                                                } else {
                                                    if (features[15] <= -0.37992f) { // tcp.ack <= -0.38
                                                        if (features[22] <= 1.15345f) { // tcp.dstport <= 1.15
                                                            if (features[17] <= -0.04564f) { // tcp.checksum <= -0.05
                                                                if (features[22] <= 0.82982f) { // tcp.dstport <= 0.83
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[17] <= -1.14589f) { // tcp.checksum <= -1.15
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[17] <= 0.01624f) { // tcp.checksum <= 0.02
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[22] <= 0.92203f) { // tcp.dstport <= 0.92
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[22] <= 1.40005f) { // tcp.dstport <= 1.40
                                                                if (features[22] <= 1.23511f) { // tcp.dstport <= 1.24
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 13; // Vulnerability_scanner
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[17] <= 1.43793f) { // tcp.checksum <= 1.44
                                                                    if (features[17] <= 0.98353f) { // tcp.checksum <= 0.98
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if (features[22] <= 1.53214f) { // tcp.dstport <= 1.53
                                                            if (features[17] <= -0.44172f) { // tcp.checksum <= -0.44
                                                                if (features[17] <= -0.60205f) { // tcp.checksum <= -0.60
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[22] <= 1.56421f) { // tcp.dstport <= 1.56
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.9000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                if (features[28] <= -0.28126f) { // tcp.seq <= -0.28
                                                    if (features[15] <= -0.37957f) { // tcp.ack <= -0.38
                                                        if (features[28] <= -0.28289f) { // tcp.seq <= -0.28
                                                            if (features[22] <= 1.75269f) { // tcp.dstport <= 1.75
                                                                if (features[17] <= -0.63869f) { // tcp.checksum <= -0.64
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[22] <= 1.72166f) { // tcp.dstport <= 1.72
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.7188f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[17] <= 0.78988f) { // tcp.checksum <= 0.79
                                                                    if (features[22] <= 1.76886f) { // tcp.dstport <= 1.77
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 5; // Fingerprinting
                                                                    *out_anomaly_score = 0.6250f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            *out_class_idx = 14; // XSS
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[15] <= -0.37954f) { // tcp.ack <= -0.38
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[15] <= -0.37935f) { // tcp.ack <= -0.38
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[15] <= -0.37921f) { // tcp.ack <= -0.38
                                                        *out_class_idx = 14; // XSS
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            if (features[22] <= 1.16499f) { // tcp.dstport <= 1.16
                                                if (features[22] <= 0.77690f) { // tcp.dstport <= 0.78
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[15] <= -0.37751f) { // tcp.ack <= -0.38
                                                        if (features[28] <= -0.28208f) { // tcp.seq <= -0.28
                                                            if (features[13] <= 2.14573f) { // http.response <= 2.15
                                                                if (features[15] <= -0.37854f) { // tcp.ack <= -0.38
                                                                    if (features[22] <= 1.04039f) { // tcp.dstport <= 1.04
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[22] <= 1.10947f) { // tcp.dstport <= 1.11
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 11; // SQL_injection
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                if (features[22] <= 1.46078f) { // tcp.dstport <= 1.46
                                                    if (features[22] <= 1.25737f) { // tcp.dstport <= 1.26
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 0.8750f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        if (features[24] <= -0.29529f) { // tcp.flags.ack <= -0.30
                                            if (features[28] <= -0.28159f) { // tcp.seq <= -0.28
                                                if (features[17] <= 0.30351f) { // tcp.checksum <= 0.30
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 0.9000f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 14; // XSS
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 3; // DDoS_TCP
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    }
                                }
                            } else {
                                if (features[22] <= -0.63367f) { // tcp.dstport <= -0.63
                                    *out_class_idx = 7; // Normal
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[29] <= -0.80541f) { // tcp.srcport <= -0.81
                                        *out_class_idx = 7; // Normal
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        if (features[22] <= 1.77887f) { // tcp.dstport <= 1.78
                                            if (features[29] <= 1.40008f) { // tcp.srcport <= 1.40
                                                if (features[22] <= 1.58237f) { // tcp.dstport <= 1.58
                                                    if (features[29] <= -0.75534f) { // tcp.srcport <= -0.76
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[22] <= -0.58324f) { // tcp.dstport <= -0.58
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[17] <= -0.97569f) { // tcp.checksum <= -0.98
                                                                if (features[17] <= -0.99122f) { // tcp.checksum <= -0.99
                                                                    *out_class_idx = 10; // Ransomware
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 0; // Backdoor
                                                                    *out_anomaly_score = 0.5000f;
                                                                    return 0;
                                                                }
                                                            } else {
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[29] <= -0.75534f) { // tcp.srcport <= -0.76
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 0; // Backdoor
                                                        *out_anomaly_score = 0.0000f;
                                                        return 0;
                                                    }
                                                }
                                            } else {
                                                if (features[22] <= -0.53014f) { // tcp.dstport <= -0.53
                                                    if (features[22] <= -0.58324f) { // tcp.dstport <= -0.58
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 0; // Backdoor
                                                        *out_anomaly_score = 0.0000f;
                                                        return 0;
                                                    }
                                                } else {
                                                    if (features[28] <= -0.21060f) { // tcp.seq <= -0.21
                                                        *out_class_idx = 5; // Fingerprinting
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 7; // Normal
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            if (features[22] <= 1.80775f) { // tcp.dstport <= 1.81
                                                *out_class_idx = 7; // Normal
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 5; // Fingerprinting
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        if (features[44] <= 0.18620f) { // mqtt.len <= 0.19
                            *out_class_idx = 3; // DDoS_TCP
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 7; // Normal
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    }
                } else {
                    if (features[15] <= -0.37568f) { // tcp.ack <= -0.38
                        if (features[25] <= 0.22198f) { // tcp.len <= 0.22
                            if (features[29] <= 1.00120f) { // tcp.srcport <= 1.00
                                *out_class_idx = 8; // Password
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[25] <= 0.09706f) { // tcp.len <= 0.10
                                    *out_class_idx = 8; // Password
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 13; // Vulnerability_scanner
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            }
                        } else {
                            if (features[15] <= -0.37945f) { // tcp.ack <= -0.38
                                *out_class_idx = 14; // XSS
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[15] <= -0.37757f) { // tcp.ack <= -0.38
                                    *out_class_idx = 1; // DDoS_HTTP
                                    *out_anomaly_score = 0.7500f;
                                    return 1;
                                } else {
                                    *out_class_idx = 1; // DDoS_HTTP
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            }
                        }
                    } else {
                        *out_class_idx = 13; // Vulnerability_scanner
                        *out_anomaly_score = 1.0000f;
                        return 1;
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
