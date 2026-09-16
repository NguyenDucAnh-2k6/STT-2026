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

        if (features[22] <= -0.73689f) { // tcp.dstport <= -0.74
            if (features[31] <= -0.28267f) { // udp.stream <= -0.28
                if (features[3] <= -0.25975f) { // icmp.seq_le <= -0.26
                    if (features[2] <= -0.08061f) { // icmp.checksum <= -0.08
                        if (features[1] <= 5.81868f) { // arp.hw.size <= 5.82
                            if (features[32] <= 0.70380f) { // udp.time_delta <= 0.70
                                *out_class_idx = 6; // MITM
                                *out_anomaly_score = 0.6439f;
                                return 1;
                            } else {
                                *out_class_idx = 6; // MITM
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            if (features[0] <= 12.96431f) { // arp.opcode <= 12.96
                                *out_class_idx = 9; // Port_Scanning
                                *out_anomaly_score = 0.7439f;
                                return 1;
                            } else {
                                *out_class_idx = 9; // Port_Scanning
                                *out_anomaly_score = 0.7812f;
                                return 1;
                            }
                        }
                    } else {
                        if (features[3] <= -0.28247f) { // icmp.seq_le <= -0.28
                            *out_class_idx = 5; // Fingerprinting
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 5; // Fingerprinting
                            *out_anomaly_score = 0.8750f;
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
        } else {
            if (features[15] <= -0.37695f) { // tcp.ack <= -0.38
                if (features[15] <= -0.38293f) { // tcp.ack <= -0.38
                    if (features[22] <= -0.73356f) { // tcp.dstport <= -0.73
                        if (features[29] <= 1.49953f) { // tcp.srcport <= 1.50
                            if (features[29] <= 0.50348f) { // tcp.srcport <= 0.50
                                if (features[29] <= 0.43988f) { // tcp.srcport <= 0.44
                                    if (features[28] <= -0.27779f) { // tcp.seq <= -0.28
                                        if (features[25] <= -0.02063f) { // tcp.len <= -0.02
                                            if (features[17] <= 1.38278f) { // tcp.checksum <= 1.38
                                                *out_class_idx = 14; // XSS
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 12; // Uploading
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    } else {
                                        *out_class_idx = 1; // DDoS_HTTP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[28] <= -0.27779f) { // tcp.seq <= -0.28
                                        if (features[25] <= 0.02602f) { // tcp.len <= 0.03
                                            if (features[23] <= -0.40323f) { // tcp.flags <= -0.40
                                                if (features[29] <= 0.45820f) { // tcp.srcport <= 0.46
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[25] <= -0.02690f) { // tcp.len <= -0.03
                                                    if (features[23] <= 0.40087f) { // tcp.flags <= 0.40
                                                        if (features[17] <= 0.03026f) { // tcp.checksum <= 0.03
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 0.9286f;
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
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            *out_class_idx = 1; // DDoS_HTTP
                                            *out_anomaly_score = 0.8571f;
                                            return 1;
                                        }
                                    } else {
                                        *out_class_idx = 1; // DDoS_HTTP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            } else {
                                if (features[29] <= 0.96075f) { // tcp.srcport <= 0.96
                                    if (features[28] <= -0.27779f) { // tcp.seq <= -0.28
                                        if (features[25] <= 0.14478f) { // tcp.len <= 0.14
                                            if (features[29] <= 0.60086f) { // tcp.srcport <= 0.60
                                                if (features[7] <= 0.03508f) { // http.content_length <= 0.04
                                                    if (features[25] <= 0.09304f) { // tcp.len <= 0.09
                                                        if (features[28] <= -0.27841f) { // tcp.seq <= -0.28
                                                            if (features[29] <= 0.54947f) { // tcp.srcport <= 0.55
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.8750f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 0.8333f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 8; // Password
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[23] <= -0.40323f) { // tcp.flags <= -0.40
                                                    if (features[29] <= 0.60668f) { // tcp.srcport <= 0.61
                                                        *out_class_idx = 11; // SQL_injection
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[29] <= 0.80779f) { // tcp.srcport <= 0.81
                                                            if (features[29] <= 0.74218f) { // tcp.srcport <= 0.74
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.7262f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.9000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[17] <= -1.05641f) { // tcp.checksum <= -1.06
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.7308f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[25] <= 0.10872f) { // tcp.len <= 0.11
                                                        if (features[23] <= 0.40087f) { // tcp.flags <= 0.40
                                                            if (features[17] <= -1.12022f) { // tcp.checksum <= -1.12
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[25] <= 0.12753f) { // tcp.len <= 0.13
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 11; // SQL_injection
                                                            *out_anomaly_score = 0.9167f;
                                                            return 1;
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            *out_class_idx = 11; // SQL_injection
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    } else {
                                        if (features[19] <= 1.38825f) { // tcp.connection.rst <= 1.39
                                            *out_class_idx = 1; // DDoS_HTTP
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 11; // SQL_injection
                                            *out_anomaly_score = 0.9091f;
                                            return 1;
                                        }
                                    }
                                } else {
                                    if (features[28] <= -0.27836f) { // tcp.seq <= -0.28
                                        if (features[29] <= 1.17059f) { // tcp.srcport <= 1.17
                                            if (features[29] <= 1.06100f) { // tcp.srcport <= 1.06
                                                if (features[17] <= -0.92952f) { // tcp.checksum <= -0.93
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[17] <= -0.46068f) { // tcp.checksum <= -0.46
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[17] <= 1.68071f) { // tcp.checksum <= 1.68
                                                            if (features[23] <= 0.40087f) { // tcp.flags <= 0.40
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.9286f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.8000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                }
                                            } else {
                                                if (features[28] <= -0.27841f) { // tcp.seq <= -0.28
                                                    if (features[29] <= 1.12436f) { // tcp.srcport <= 1.12
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 0.7727f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 0.7500f;
                                                        return 1;
                                                    }
                                                } else {
                                                    if (features[25] <= 0.08794f) { // tcp.len <= 0.09
                                                        if (features[23] <= 0.77612f) { // tcp.flags <= 0.78
                                                            if (features[29] <= 1.10813f) { // tcp.srcport <= 1.11
                                                                *out_class_idx = 13; // Vulnerability_scanner
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
                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            if (features[29] <= 1.35875f) { // tcp.srcport <= 1.36
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[29] <= 1.46527f) { // tcp.srcport <= 1.47
                                                    if (features[29] <= 1.42998f) { // tcp.srcport <= 1.43
                                                        if (features[17] <= 1.07612f) { // tcp.checksum <= 1.08
                                                            if (features[17] <= 0.31535f) { // tcp.checksum <= 0.32
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.8462f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 0.8889f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 0.9500f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        if (features[19] <= 1.38825f) { // tcp.connection.rst <= 1.39
                                            *out_class_idx = 1; // DDoS_HTTP
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 1; // DDoS_HTTP
                                            *out_anomaly_score = 0.8571f;
                                            return 1;
                                        }
                                    }
                                }
                            }
                        } else {
                            if (features[28] <= -0.27756f) { // tcp.seq <= -0.28
                                if (features[24] <= -0.29494f) { // tcp.flags.ack <= -0.29
                                    if (features[29] <= 1.51002f) { // tcp.srcport <= 1.51
                                        *out_class_idx = 12; // Uploading
                                        *out_anomaly_score = 0.7857f;
                                        return 1;
                                    } else {
                                        if (features[29] <= 1.51961f) { // tcp.srcport <= 1.52
                                            *out_class_idx = 14; // XSS
                                            *out_anomaly_score = 0.9000f;
                                            return 1;
                                        } else {
                                            if (features[17] <= 1.55799f) { // tcp.checksum <= 1.56
                                                if (features[29] <= 1.52207f) { // tcp.srcport <= 1.52
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
                                                } else {
                                                    if (features[17] <= -0.72561f) { // tcp.checksum <= -0.73
                                                        *out_class_idx = 14; // XSS
                                                        *out_anomaly_score = 0.8889f;
                                                        return 1;
                                                    } else {
                                                        if (features[17] <= 1.07266f) { // tcp.checksum <= 1.07
                                                            if (features[29] <= 1.53429f) { // tcp.srcport <= 1.53
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.7273f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 14; // XSS
                                                            *out_anomaly_score = 0.9167f;
                                                            return 1;
                                                        }
                                                    }
                                                }
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 0.8333f;
                                                return 1;
                                            }
                                        }
                                    }
                                } else {
                                    if (features[29] <= 1.50183f) { // tcp.srcport <= 1.50
                                        *out_class_idx = 12; // Uploading
                                        *out_anomaly_score = 0.8000f;
                                        return 1;
                                    } else {
                                        if (features[25] <= -0.02063f) { // tcp.len <= -0.02
                                            if (features[25] <= -0.02886f) { // tcp.len <= -0.03
                                                if (features[15] <= -0.38320f) { // tcp.ack <= -0.38
                                                    if (features[29] <= 1.57564f) { // tcp.srcport <= 1.58
                                                        if (features[17] <= 0.44941f) { // tcp.checksum <= 0.45
                                                            if (features[29] <= 1.52961f) { // tcp.srcport <= 1.53
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.7667f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.9667f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[17] <= 1.29145f) { // tcp.checksum <= 1.29
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.8636f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.8077f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 0.7222f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 8; // Password
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 14; // XSS
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[25] <= -0.01396f) { // tcp.len <= -0.01
                                                *out_class_idx = 12; // Uploading
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
                            } else {
                                *out_class_idx = 1; // DDoS_HTTP
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        }
                    } else {
                        if (features[29] <= -0.90429f) { // tcp.srcport <= -0.90
                            if (features[22] <= 0.17753f) { // tcp.dstport <= 0.18
                                *out_class_idx = 9; // Port_Scanning
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[22] <= 1.69887f) { // tcp.dstport <= 1.70
                                    if (features[22] <= 0.71341f) { // tcp.dstport <= 0.71
                                        if (features[22] <= 0.63577f) { // tcp.dstport <= 0.64
                                            *out_class_idx = 14; // XSS
                                            *out_anomaly_score = 0.9500f;
                                            return 1;
                                        } else {
                                            if (features[22] <= 0.66069f) { // tcp.dstport <= 0.66
                                                *out_class_idx = 12; // Uploading
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[17] <= 0.38465f) { // tcp.checksum <= 0.38
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 0.9000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 8; // Password
                                                    *out_anomaly_score = 0.9167f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        if (features[22] <= 1.16143f) { // tcp.dstport <= 1.16
                                            if (features[21] <= 2.62751f) { // tcp.connection.synack <= 2.63
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 0.9375f;
                                                return 1;
                                            } else {
                                                if (features[22] <= 0.78733f) { // tcp.dstport <= 0.79
                                                    *out_class_idx = 8; // Password
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[17] <= -0.04788f) { // tcp.checksum <= -0.05
                                                        if (features[17] <= -0.29443f) { // tcp.checksum <= -0.29
                                                            if (features[17] <= -0.61972f) { // tcp.checksum <= -0.62
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.9286f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 11; // SQL_injection
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[22] <= 0.97967f) { // tcp.dstport <= 0.98
                                                            if (features[22] <= 0.92944f) { // tcp.dstport <= 0.93
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[22] <= 1.01808f) { // tcp.dstport <= 1.02
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.8571f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.7857f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            if (features[15] <= -0.38309f) { // tcp.ack <= -0.38
                                                if (features[22] <= 1.39338f) { // tcp.dstport <= 1.39
                                                    if (features[22] <= 1.28209f) { // tcp.dstport <= 1.28
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 0.7778f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                        *out_anomaly_score = 0.8750f;
                                                        return 1;
                                                    }
                                                } else {
                                                    if (features[17] <= 1.43658f) { // tcp.checksum <= 1.44
                                                        if (features[22] <= 1.54946f) { // tcp.dstport <= 1.55
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 0.9000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    }
                                } else {
                                    if (features[22] <= 1.73641f) { // tcp.dstport <= 1.74
                                        if (features[17] <= -1.08116f) { // tcp.checksum <= -1.08
                                            *out_class_idx = 12; // Uploading
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            if (features[22] <= 1.73259f) { // tcp.dstport <= 1.73
                                                if (features[17] <= -0.86546f) { // tcp.checksum <= -0.87
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 0.7727f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 12; // Uploading
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        if (features[28] <= -0.27709f) { // tcp.seq <= -0.28
                                            if (features[15] <= -0.38321f) { // tcp.ack <= -0.38
                                                *out_class_idx = 12; // Uploading
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[17] <= -0.61709f) { // tcp.checksum <= -0.62
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 0.9444f;
                                                    return 1;
                                                } else {
                                                    if (features[17] <= 1.59597f) { // tcp.checksum <= 1.60
                                                        if (features[17] <= 1.43449f) { // tcp.checksum <= 1.43
                                                            if (features[22] <= 1.77411f) { // tcp.dstport <= 1.77
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.8571f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 0.7273f;
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
                                                }
                                            }
                                        } else {
                                            *out_class_idx = 14; // XSS
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    }
                                }
                            }
                        } else {
                            if (features[25] <= -0.03317f) { // tcp.len <= -0.03
                                if (features[15] <= -0.38320f) { // tcp.ack <= -0.38
                                    if (features[22] <= -0.63038f) { // tcp.dstport <= -0.63
                                        if (features[29] <= 1.76546f) { // tcp.srcport <= 1.77
                                            *out_class_idx = 7; // Normal
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 5; // Fingerprinting
                                            *out_anomaly_score = 0.7500f;
                                            return 1;
                                        }
                                    } else {
                                        if (features[29] <= -0.80933f) { // tcp.srcport <= -0.81
                                            if (features[22] <= 1.97470f) { // tcp.dstport <= 1.97
                                                *out_class_idx = 7; // Normal
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 5; // Fingerprinting
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[29] <= -0.75937f) { // tcp.srcport <= -0.76
                                                *out_class_idx = 12; // Uploading
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[22] <= -0.57981f) { // tcp.dstport <= -0.58
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[29] <= 1.25108f) { // tcp.srcport <= 1.25
                                                        if (features[22] <= 1.49662f) { // tcp.dstport <= 1.50
                                                            if (features[17] <= -0.96113f) { // tcp.checksum <= -0.96
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 0.9919f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[23] <= -0.18880f) { // tcp.flags <= -0.19
                                                                *out_class_idx = 5; // Fingerprinting
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 0; // Backdoor
                                                                *out_anomaly_score = 0.0000f;
                                                                return 0;
                                                            }
                                                        }
                                                    } else {
                                                        if (features[22] <= -0.22776f) { // tcp.dstport <= -0.23
                                                            *out_class_idx = 0; // Backdoor
                                                            *out_anomaly_score = 0.0000f;
                                                            return 0;
                                                        } else {
                                                            *out_class_idx = 5; // Fingerprinting
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    *out_class_idx = 7; // Normal
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            } else {
                                if (features[29] <= 1.22002f) { // tcp.srcport <= 1.22
                                    if (features[29] <= -0.07182f) { // tcp.srcport <= -0.07
                                        *out_class_idx = 12; // Uploading
                                        *out_anomaly_score = 0.9500f;
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
                            }
                        }
                    }
                } else {
                    if (features[15] <= -0.38271f) { // tcp.ack <= -0.38
                        if (features[19] <= 1.38825f) { // tcp.connection.rst <= 1.39
                            if (features[15] <= -0.38286f) { // tcp.ack <= -0.38
                                if (features[15] <= -0.38289f) { // tcp.ack <= -0.38
                                    *out_class_idx = 8; // Password
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 14; // XSS
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            } else {
                                if (features[28] <= -0.27699f) { // tcp.seq <= -0.28
                                    if (features[7] <= 1.39716f) { // http.content_length <= 1.40
                                        if (features[28] <= -0.27817f) { // tcp.seq <= -0.28
                                            if (features[15] <= -0.38283f) { // tcp.ack <= -0.38
                                                *out_class_idx = 12; // Uploading
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 14; // XSS
                                                *out_anomaly_score = 0.9000f;
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
                                    *out_class_idx = 14; // XSS
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
                        if (features[29] <= 1.50109f) { // tcp.srcport <= 1.50
                            if (features[15] <= -0.38220f) { // tcp.ack <= -0.38
                                if (features[15] <= -0.38248f) { // tcp.ack <= -0.38
                                    if (features[28] <= -0.27742f) { // tcp.seq <= -0.28
                                        *out_class_idx = 1; // DDoS_HTTP
                                        *out_anomaly_score = 0.7500f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 14; // XSS
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[22] <= 1.54084f) { // tcp.dstport <= 1.54
                                        if (features[15] <= -0.38231f) { // tcp.ack <= -0.38
                                            if (features[17] <= -0.73884f) { // tcp.checksum <= -0.74
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 0.9583f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[29] <= -0.23645f) { // tcp.srcport <= -0.24
                                                *out_class_idx = 11; // SQL_injection
                                                *out_anomaly_score = 0.8333f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        if (features[22] <= 1.57095f) { // tcp.dstport <= 1.57
                                            *out_class_idx = 1; // DDoS_HTTP
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            if (features[15] <= -0.38234f) { // tcp.ack <= -0.38
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            } else {
                                if (features[15] <= -0.38084f) { // tcp.ack <= -0.38
                                    if (features[22] <= 1.16877f) { // tcp.dstport <= 1.17
                                        if (features[15] <= -0.38163f) { // tcp.ack <= -0.38
                                            if (features[28] <= -0.27727f) { // tcp.seq <= -0.28
                                                if (features[28] <= -0.27818f) { // tcp.seq <= -0.28
                                                    if (features[13] <= 2.14995f) { // http.response <= 2.15
                                                        if (features[22] <= 0.77236f) { // tcp.dstport <= 0.77
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[15] <= -0.38207f) { // tcp.ack <= -0.38
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.9688f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.7857f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        *out_class_idx = 11; // SQL_injection
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 11; // SQL_injection
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[22] <= 0.81516f) { // tcp.dstport <= 0.82
                                                if (features[15] <= -0.38160f) { // tcp.ack <= -0.38
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[29] <= 0.90321f) { // tcp.srcport <= 0.90
                                                        if (features[28] <= -0.27332f) { // tcp.seq <= -0.27
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[29] <= 1.24752f) { // tcp.srcport <= 1.25
                                                            *out_class_idx = 13; // Vulnerability_scanner
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
                                                if (features[28] <= -0.27734f) { // tcp.seq <= -0.28
                                                    if (features[25] <= 0.08442f) { // tcp.len <= 0.08
                                                        if (features[17] <= 0.90522f) { // tcp.checksum <= 0.91
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.7917f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 11; // SQL_injection
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    if (features[22] <= 1.11846f) { // tcp.dstport <= 1.12
                                                        *out_class_idx = 11; // SQL_injection
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 0.7500f;
                                                        return 1;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        if (features[28] <= -0.27623f) { // tcp.seq <= -0.28
                                            if (features[22] <= 1.46008f) { // tcp.dstport <= 1.46
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 0.8182f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 13; // Vulnerability_scanner
                                            *out_anomaly_score = 0.9545f;
                                            return 1;
                                        }
                                    }
                                } else {
                                    if (features[29] <= -0.84628f) { // tcp.srcport <= -0.85
                                        if (features[28] <= -0.27510f) { // tcp.seq <= -0.28
                                            if (features[18] <= 1.92548f) { // tcp.connection.fin <= 1.93
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 13; // Vulnerability_scanner
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    } else {
                                        if (features[28] <= -0.27696f) { // tcp.seq <= -0.28
                                            if (features[29] <= 0.46111f) { // tcp.srcport <= 0.46
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 8; // Password
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[22] <= -0.72771f) { // tcp.dstport <= -0.73
                                                *out_class_idx = 13; // Vulnerability_scanner
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 12; // Uploading
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if (features[28] <= -0.27746f) { // tcp.seq <= -0.28
                                if (features[28] <= -0.27799f) { // tcp.seq <= -0.28
                                    *out_class_idx = 8; // Password
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 14; // XSS
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                }
                            } else {
                                *out_class_idx = 8; // Password
                                *out_anomaly_score = 0.7778f;
                                return 1;
                            }
                        }
                    }
                }
            } else {
                if (features[28] <= -0.27730f) { // tcp.seq <= -0.28
                    if (features[24] <= -0.29494f) { // tcp.flags.ack <= -0.29
                        if (features[25] <= -0.05551f) { // tcp.len <= -0.06
                            *out_class_idx = 9; // Port_Scanning
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 3; // DDoS_TCP
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        if (features[22] <= 1.42345f) { // tcp.dstport <= 1.42
                            if (features[29] <= 0.24247f) { // tcp.srcport <= 0.24
                                *out_class_idx = 10; // Ransomware
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                *out_class_idx = 12; // Uploading
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            *out_class_idx = 0; // Backdoor
                            *out_anomaly_score = 0.0000f;
                            return 0;
                        }
                    }
                } else {
                    if (features[28] <= -0.00795f) { // tcp.seq <= -0.01
                        if (features[15] <= -0.18302f) { // tcp.ack <= -0.18
                            if (features[22] <= 1.49065f) { // tcp.dstport <= 1.49
                                *out_class_idx = 13; // Vulnerability_scanner
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                *out_class_idx = 0; // Backdoor
                                *out_anomaly_score = 0.0000f;
                                return 0;
                            }
                        } else {
                            *out_class_idx = 12; // Uploading
                            *out_anomaly_score = 0.9375f;
                            return 1;
                        }
                    } else {
                        *out_class_idx = 7; // Normal
                        *out_anomaly_score = 1.0000f;
                        return 1;
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
