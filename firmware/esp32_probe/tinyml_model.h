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

        if (features[31] <= -0.28199f) { // udp.stream <= -0.28
            if (features[3] <= -0.25989f) { // icmp.seq_le <= -0.26
                if (features[7] <= -0.14893f) { // http.content_length <= -0.15
                    if (features[27] <= 2.18737f) { // tcp.payload <= 2.19
                        if (features[22] <= -0.66543f) { // tcp.dstport <= -0.67
                            if (features[15] <= 1.35186f) { // tcp.ack <= 1.35
                                if (features[29] <= 1.50519f) { // tcp.srcport <= 1.51
                                    if (features[29] <= 0.51110f) { // tcp.srcport <= 0.51
                                        if (features[29] <= 0.43174f) { // tcp.srcport <= 0.43
                                            if (features[2] <= -0.24387f) { // icmp.checksum <= -0.24
                                                if (features[27] <= -0.21992f) { // tcp.payload <= -0.22
                                                    if (features[0] <= 3.20773f) { // arp.opcode <= 3.21
                                                        if (features[22] <= -0.68695f) { // tcp.dstport <= -0.69
                                                            if (features[19] <= 1.37107f) { // tcp.connection.rst <= 1.37
                                                                if (features[32] <= 5.12979f) { // udp.time_delta <= 5.13
                                                                    *out_class_idx = 6; // MITM
                                                                    *out_anomaly_score = 0.6455f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 7; // Normal
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 3; // DDoS_TCP
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[15] <= -0.38214f) { // tcp.ack <= -0.38
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
                                                        if (features[0] <= 9.81162f) { // arp.opcode <= 9.81
                                                            *out_class_idx = 9; // Port_Scanning
                                                            *out_anomaly_score = 0.7654f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 9; // Port_Scanning
                                                            *out_anomaly_score = 0.7105f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    *out_class_idx = 6; // MITM
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[3] <= -0.28139f) { // icmp.seq_le <= -0.28
                                                    *out_class_idx = 5; // Fingerprinting
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[3] <= -0.26253f) { // icmp.seq_le <= -0.26
                                                        *out_class_idx = 2; // DDoS_ICMP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 5; // Fingerprinting
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            if (features[28] <= -0.26832f) { // tcp.seq <= -0.27
                                                if (features[29] <= 0.44451f) { // tcp.srcport <= 0.44
                                                    if (features[15] <= -0.38137f) { // tcp.ack <= -0.38
                                                        if (features[28] <= -0.26909f) { // tcp.seq <= -0.27
                                                            if (features[25] <= -0.01963f) { // tcp.len <= -0.02
                                                                if (features[17] <= 1.63094f) { // tcp.checksum <= 1.63
                                                                    if (features[29] <= 0.43583f) { // tcp.srcport <= 0.44
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.7708f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.9082f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[25] <= -0.01364f) { // tcp.len <= -0.01
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[15] <= -0.37866f) { // tcp.ack <= -0.38
                                                            *out_class_idx = 14; // XSS
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[20] <= 1.11931f) { // tcp.connection.syn <= 1.12
                                                        if (features[25] <= 0.08894f) { // tcp.len <= 0.09
                                                            if (features[15] <= -0.38160f) { // tcp.ack <= -0.38
                                                                if (features[25] <= 0.02492f) { // tcp.len <= 0.02
                                                                    if (features[28] <= -0.26933f) { // tcp.seq <= -0.27
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.9267f;
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
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[29] <= 0.45638f) { // tcp.srcport <= 0.46
                                                            if (features[17] <= -0.71714f) { // tcp.checksum <= -0.72
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            } else {
                                                                if (features[29] <= 0.44889f) { // tcp.srcport <= 0.45
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[29] <= 0.45032f) { // tcp.srcport <= 0.45
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[29] <= 0.50198f) { // tcp.srcport <= 0.50
                                                                if (features[29] <= 0.48642f) { // tcp.srcport <= 0.49
                                                                    if (features[29] <= 0.47115f) { // tcp.srcport <= 0.47
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8529f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.7778f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= -1.03699f) { // tcp.checksum <= -1.04
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8889f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[29] <= 0.50496f) { // tcp.srcport <= 0.50
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[17] <= 0.06137f) { // tcp.checksum <= 0.06
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    }
                                                                }
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
                                        if (features[29] <= 0.96501f) { // tcp.srcport <= 0.97
                                            if (features[15] <= -0.38124f) { // tcp.ack <= -0.38
                                                if (features[28] <= -0.26832f) { // tcp.seq <= -0.27
                                                    if (features[25] <= 0.13687f) { // tcp.len <= 0.14
                                                        if (features[28] <= -0.26958f) { // tcp.seq <= -0.27
                                                            if (features[28] <= -0.26958f) { // tcp.seq <= -0.27
                                                                if (features[29] <= 0.60644f) { // tcp.srcport <= 0.61
                                                                    if (features[17] <= 1.53258f) { // tcp.checksum <= 1.53
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.9426f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7778f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= -1.19131f) { // tcp.checksum <= -1.19
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7484f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[25] <= 0.08894f) { // tcp.len <= 0.09
                                                                    if (features[23] <= 0.41177f) { // tcp.flags <= 0.41
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.8261f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[25] <= 0.11290f) { // tcp.len <= 0.11
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[28] <= -0.26937f) { // tcp.seq <= -0.27
                                                                if (features[17] <= -0.17708f) { // tcp.checksum <= -0.18
                                                                    if (features[17] <= -0.20580f) { // tcp.checksum <= -0.21
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
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        if (features[29] <= 0.60840f) { // tcp.srcport <= 0.61
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[25] <= 0.14061f) { // tcp.len <= 0.14
                                                                if (features[29] <= 0.83783f) { // tcp.srcport <= 0.84
                                                                    *out_class_idx = 11; // SQL_injection
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[29] <= 0.86513f) { // tcp.srcport <= 0.87
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[19] <= 1.37107f) { // tcp.connection.rst <= 1.37
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[28] <= -0.26636f) { // tcp.seq <= -0.27
                                                            if (features[28] <= -0.26655f) { // tcp.seq <= -0.27
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 0.8333f;
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
                                                if (features[15] <= -0.38076f) { // tcp.ack <= -0.38
                                                    *out_class_idx = 11; // SQL_injection
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[28] <= -0.26786f) { // tcp.seq <= -0.27
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[22] <= -0.73207f) { // tcp.dstport <= -0.73
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 13; // Vulnerability_scanner
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            if (features[15] <= -0.38233f) { // tcp.ack <= -0.38
                                                if (features[28] <= -0.26953f) { // tcp.seq <= -0.27
                                                    if (features[25] <= 0.08894f) { // tcp.len <= 0.09
                                                        if (features[24] <= -0.28266f) { // tcp.flags.ack <= -0.28
                                                            if (features[29] <= 1.37769f) { // tcp.srcport <= 1.38
                                                                if (features[29] <= 1.13529f) { // tcp.srcport <= 1.14
                                                                    if (features[29] <= 1.07434f) { // tcp.srcport <= 1.07
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8735f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7941f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[29] <= 1.18592f) { // tcp.srcport <= 1.19
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9839f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[29] <= 1.50220f) { // tcp.srcport <= 1.50
                                                                    if (features[29] <= 1.47597f) { // tcp.srcport <= 1.48
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8839f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.9412f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 0.9000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[29] <= 1.48620f) { // tcp.srcport <= 1.49
                                                                if (features[29] <= 1.18666f) { // tcp.srcport <= 1.19
                                                                    if (features[29] <= 1.06787f) { // tcp.srcport <= 1.07
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9565f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7593f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[29] <= 1.32701f) { // tcp.srcport <= 1.33
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9886f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8605f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[29] <= 1.50028f) { // tcp.srcport <= 1.50
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.8750f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 0.9000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if (features[25] <= 0.26454f) { // tcp.len <= 0.26
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
                                                    if (features[24] <= -0.28266f) { // tcp.flags.ack <= -0.28
                                                        if (features[29] <= 1.08932f) { // tcp.srcport <= 1.09
                                                            if (features[28] <= -0.26766f) { // tcp.seq <= -0.27
                                                                *out_class_idx = 13; // Vulnerability_scanner
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 1; // DDoS_HTTP
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[29] <= 1.26971f) { // tcp.srcport <= 1.27
                                                                *out_class_idx = 13; // Vulnerability_scanner
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 8; // Password
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
                                            } else {
                                                if (features[28] <= -0.26835f) { // tcp.seq <= -0.27
                                                    if (features[29] <= 1.50016f) { // tcp.srcport <= 1.50
                                                        if (features[22] <= -0.73084f) { // tcp.dstport <= -0.73
                                                            if (features[25] <= -0.04247f) { // tcp.len <= -0.04
                                                                if (features[15] <= -0.37915f) { // tcp.ack <= -0.38
                                                                    if (features[15] <= -0.38104f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                                        *out_anomaly_score = 0.7917f;
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
                                                        } else {
                                                            *out_class_idx = 7; // Normal
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[29] <= 1.50487f) { // tcp.srcport <= 1.50
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[29] <= 1.22255f) { // tcp.srcport <= 1.22
                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[22] <= -0.73207f) { // tcp.dstport <= -0.73
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
                                    if (features[15] <= -0.38112f) { // tcp.ack <= -0.38
                                        if (features[15] <= -0.38209f) { // tcp.ack <= -0.38
                                            if (features[28] <= -0.26845f) { // tcp.seq <= -0.27
                                                if (features[25] <= 0.05562f) { // tcp.len <= 0.06
                                                    if (features[25] <= -0.01963f) { // tcp.len <= -0.02
                                                        if (features[25] <= -0.02750f) { // tcp.len <= -0.03
                                                            if (features[15] <= -0.38233f) { // tcp.ack <= -0.38
                                                                if (features[23] <= -1.03437f) { // tcp.flags <= -1.03
                                                                    if (features[29] <= 1.50573f) { // tcp.srcport <= 1.51
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.7729f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[23] <= 0.41177f) { // tcp.flags <= 0.41
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8309f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 5; // Fingerprinting
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[29] <= 1.52271f) { // tcp.srcport <= 1.52
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            *out_class_idx = 14; // XSS
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[25] <= -0.01514f) { // tcp.len <= -0.02
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 14; // XSS
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
                                        } else {
                                            if (features[15] <= -0.38160f) { // tcp.ack <= -0.38
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
                                        if (features[15] <= -0.38075f) { // tcp.ack <= -0.38
                                            *out_class_idx = 14; // XSS
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            if (features[15] <= -0.37866f) { // tcp.ack <= -0.38
                                                *out_class_idx = 1; // DDoS_HTTP
                                                *out_anomaly_score = 1.0000f;
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
                                *out_class_idx = 9; // Port_Scanning
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            }
                        } else {
                            if (features[29] <= -0.89033f) { // tcp.srcport <= -0.89
                                if (features[19] <= 1.37107f) { // tcp.connection.rst <= 1.37
                                    if (features[15] <= -0.38147f) { // tcp.ack <= -0.38
                                        if (features[22] <= 1.70790f) { // tcp.dstport <= 1.71
                                            if (features[22] <= 0.69811f) { // tcp.dstport <= 0.70
                                                if (features[22] <= 0.63197f) { // tcp.dstport <= 0.63
                                                    if (features[13] <= 2.14750f) { // http.response <= 2.15
                                                        if (features[15] <= -0.38164f) { // tcp.ack <= -0.38
                                                            if (features[28] <= -0.26821f) { // tcp.seq <= -0.27
                                                                if (features[15] <= -0.38199f) { // tcp.ack <= -0.38
                                                                    if (features[23] <= 0.41177f) { // tcp.flags <= 0.41
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8500f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[15] <= -0.38197f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[17] <= 1.59913f) { // tcp.checksum <= 1.60
                                                                    *out_class_idx = 14; // XSS
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                }
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
                                                } else {
                                                    if (features[15] <= -0.38180f) { // tcp.ack <= -0.38
                                                        if (features[15] <= -0.38202f) { // tcp.ack <= -0.38
                                                            if (features[28] <= -0.26958f) { // tcp.seq <= -0.27
                                                                if (features[17] <= -0.96475f) { // tcp.checksum <= -0.96
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[17] <= -0.10537f) { // tcp.checksum <= -0.11
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.9545f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.8429f;
                                                                        return 1;
                                                                    }
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
                                                    } else {
                                                        *out_class_idx = 8; // Password
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                }
                                            } else {
                                                if (features[15] <= -0.38233f) { // tcp.ack <= -0.38
                                                    if (features[22] <= 1.16522f) { // tcp.dstport <= 1.17
                                                        if (features[22] <= 0.80356f) { // tcp.dstport <= 0.80
                                                            if (features[22] <= 0.77992f) { // tcp.dstport <= 0.78
                                                                if (features[17] <= -0.60615f) { // tcp.checksum <= -0.61
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[17] <= -0.36147f) { // tcp.checksum <= -0.36
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9286f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[17] <= 0.45718f) { // tcp.checksum <= 0.46
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.9000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[22] <= 0.82184f) { // tcp.dstport <= 0.82
                                                                *out_class_idx = 11; // SQL_injection
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                if (features[17] <= -0.16601f) { // tcp.checksum <= -0.17
                                                                    if (features[17] <= -0.66348f) { // tcp.checksum <= -0.66
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.9107f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= -0.12200f) { // tcp.checksum <= -0.12
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.7817f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if (features[22] <= 1.38189f) { // tcp.dstport <= 1.38
                                                            if (features[22] <= 1.26643f) { // tcp.dstport <= 1.27
                                                                if (features[17] <= -0.31072f) { // tcp.checksum <= -0.31
                                                                    if (features[17] <= -0.90951f) { // tcp.checksum <= -0.91
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7857f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[22] <= 1.24213f) { // tcp.dstport <= 1.24
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[17] <= 1.03201f) { // tcp.checksum <= 1.03
                                                                    if (features[22] <= 1.30702f) { // tcp.dstport <= 1.31
                                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                                        *out_anomaly_score = 0.8636f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7692f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= 1.27916f) { // tcp.checksum <= 1.28
                                                                        *out_class_idx = 8; // Password
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
                                                            if (features[22] <= 1.64953f) { // tcp.dstport <= 1.65
                                                                if (features[22] <= 1.55028f) { // tcp.dstport <= 1.55
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[22] <= 1.55809f) { // tcp.dstport <= 1.56
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9474f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[22] <= 1.65319f) { // tcp.dstport <= 1.65
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[17] <= 1.49570f) { // tcp.checksum <= 1.50
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9286f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[22] <= 1.52884f) { // tcp.dstport <= 1.53
                                                        if (features[22] <= 1.27312f) { // tcp.dstport <= 1.27
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[22] <= 1.27873f) { // tcp.dstport <= 1.28
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.8000f;
                                                                return 1;
                                                            } else {
                                                                if (features[15] <= -0.38148f) { // tcp.ack <= -0.38
                                                                    if (features[22] <= 1.52169f) { // tcp.dstport <= 1.52
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9891f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[22] <= 1.37894f) { // tcp.dstport <= 1.38
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8000f;
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
                                                        if (features[22] <= 1.58252f) { // tcp.dstport <= 1.58
                                                            if (features[28] <= -0.26958f) { // tcp.seq <= -0.27
                                                                if (features[25] <= 0.01519f) { // tcp.len <= 0.02
                                                                    if (features[15] <= -0.38150f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.9649f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[15] <= -0.38206f) { // tcp.ack <= -0.38
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[15] <= -0.38157f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[22] <= 1.70545f) { // tcp.dstport <= 1.71
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                if (features[23] <= 0.41177f) { // tcp.flags <= 0.41
                                                                    *out_class_idx = 8; // Password
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
                                                }
                                            }
                                        } else {
                                            if (features[28] <= -0.26785f) { // tcp.seq <= -0.27
                                                if (features[15] <= -0.38199f) { // tcp.ack <= -0.38
                                                    if (features[15] <= -0.38203f) { // tcp.ack <= -0.38
                                                        if (features[15] <= -0.38233f) { // tcp.ack <= -0.38
                                                            if (features[17] <= 0.36661f) { // tcp.checksum <= 0.37
                                                                if (features[17] <= -0.66737f) { // tcp.checksum <= -0.67
                                                                    if (features[17] <= -1.01352f) { // tcp.checksum <= -1.01
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.9242f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[22] <= 1.72768f) { // tcp.dstport <= 1.73
                                                                        *out_class_idx = 12; // Uploading
                                                                        *out_anomaly_score = 0.8125f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.7979f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[17] <= 1.16545f) { // tcp.checksum <= 1.17
                                                                    if (features[22] <= 1.78759f) { // tcp.dstport <= 1.79
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8846f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[17] <= 1.25781f) { // tcp.checksum <= 1.26
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7778f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8378f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        *out_class_idx = 14; // XSS
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    }
                                                } else {
                                                    if (features[15] <= -0.38197f) { // tcp.ack <= -0.38
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[15] <= -0.38176f) { // tcp.ack <= -0.38
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
                                                if (features[28] <= -0.26436f) { // tcp.seq <= -0.26
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
                                        if (features[22] <= 1.16061f) { // tcp.dstport <= 1.16
                                            if (features[15] <= -0.37997f) { // tcp.ack <= -0.38
                                                if (features[22] <= 0.79492f) { // tcp.dstport <= 0.79
                                                    if (features[22] <= 0.72416f) { // tcp.dstport <= 0.72
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[22] <= 0.72853f) { // tcp.dstport <= 0.73
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[28] <= -0.26873f) { // tcp.seq <= -0.27
                                                        if (features[13] <= 2.14750f) { // http.response <= 2.15
                                                            if (features[15] <= -0.38086f) { // tcp.ack <= -0.38
                                                                if (features[15] <= -0.38132f) { // tcp.ack <= -0.38
                                                                    if (features[15] <= -0.38139f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[15] <= -0.38120f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.9643f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.8621f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[15] <= -0.38041f) { // tcp.ack <= -0.38
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[15] <= -0.38025f) { // tcp.ack <= -0.38
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.8214f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.9062f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            *out_class_idx = 11; // SQL_injection
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[28] <= -0.26733f) { // tcp.seq <= -0.27
                                                            *out_class_idx = 11; // SQL_injection
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
                                                if (features[15] <= -0.37861f) { // tcp.ack <= -0.38
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
                                            if (features[28] <= -0.26731f) { // tcp.seq <= -0.27
                                                if (features[22] <= 1.45979f) { // tcp.dstport <= 1.46
                                                    if (features[22] <= 1.29314f) { // tcp.dstport <= 1.29
                                                        if (features[22] <= 1.26427f) { // tcp.dstport <= 1.26
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[22] <= 1.27204f) { // tcp.dstport <= 1.27
                                                                *out_class_idx = 13; // Vulnerability_scanner
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                if (features[17] <= -0.26781f) { // tcp.checksum <= -0.27
                                                                    *out_class_idx = 13; // Vulnerability_scanner
                                                                    *out_anomaly_score = 0.8333f;
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
                                                } else {
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[29] <= -0.89896f) { // tcp.srcport <= -0.90
                                                    *out_class_idx = 13; // Vulnerability_scanner
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (features[15] <= -0.38214f) { // tcp.ack <= -0.38
                                        if (features[16] <= -1.30678f) { // tcp.ack_raw <= -1.31
                                            if (features[28] <= -0.26820f) { // tcp.seq <= -0.27
                                                if (features[28] <= -0.26923f) { // tcp.seq <= -0.27
                                                    if (features[17] <= -0.07572f) { // tcp.checksum <= -0.08
                                                        *out_class_idx = 1; // DDoS_HTTP
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
                                                if (features[22] <= 1.35389f) { // tcp.dstport <= 1.35
                                                    if (features[22] <= 0.62819f) { // tcp.dstport <= 0.63
                                                        *out_class_idx = 14; // XSS
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 0.7500f;
                                                        return 1;
                                                    }
                                                } else {
                                                    *out_class_idx = 14; // XSS
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            *out_class_idx = 9; // Port_Scanning
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    } else {
                                        *out_class_idx = 3; // DDoS_TCP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            } else {
                                if (features[22] <= -0.63458f) { // tcp.dstport <= -0.63
                                    *out_class_idx = 7; // Normal
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[29] <= -0.80291f) { // tcp.srcport <= -0.80
                                        if (features[22] <= 1.97918f) { // tcp.dstport <= 1.98
                                            *out_class_idx = 7; // Normal
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 5; // Fingerprinting
                                            *out_anomaly_score = 0.7500f;
                                            return 1;
                                        }
                                    } else {
                                        if (features[29] <= 1.39521f) { // tcp.srcport <= 1.40
                                            if (features[22] <= 1.59681f) { // tcp.dstport <= 1.60
                                                if (features[29] <= -0.75302f) { // tcp.srcport <= -0.75
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[22] <= -0.58393f) { // tcp.dstport <= -0.58
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[28] <= -0.26958f) { // tcp.seq <= -0.27
                                                            if (features[29] <= 0.74909f) { // tcp.srcport <= 0.75
                                                                *out_class_idx = 0; // Backdoor
                                                                *out_anomaly_score = 0.0000f;
                                                                return 0;
                                                            } else {
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[19] <= 1.37107f) { // tcp.connection.rst <= 1.37
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                if (features[22] <= 0.94079f) { // tcp.dstport <= 0.94
                                                                    *out_class_idx = 0; // Backdoor
                                                                    *out_anomaly_score = 0.0000f;
                                                                    return 0;
                                                                } else {
                                                                    *out_class_idx = 10; // Ransomware
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                if (features[28] <= 1.01094f) { // tcp.seq <= 1.01
                                                    if (features[15] <= -0.38234f) { // tcp.ack <= -0.38
                                                        *out_class_idx = 5; // Fingerprinting
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[29] <= -0.75302f) { // tcp.srcport <= -0.75
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
                                                    *out_class_idx = 7; // Normal
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[22] <= -0.55589f) { // tcp.dstport <= -0.56
                                                if (features[22] <= -0.58393f) { // tcp.dstport <= -0.58
                                                    *out_class_idx = 12; // Uploading
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Backdoor
                                                    *out_anomaly_score = 0.0000f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[15] <= 0.14477f) { // tcp.ack <= 0.14
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
                                    }
                                }
                            }
                        }
                    } else {
                        if (features[24] <= -0.28266f) { // tcp.flags.ack <= -0.28
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
                    if (features[15] <= -0.38159f) { // tcp.ack <= -0.38
                        if (features[25] <= 0.22747f) { // tcp.len <= 0.23
                            if (features[7] <= 0.23643f) { // http.content_length <= 0.24
                                *out_class_idx = 13; // Vulnerability_scanner
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[29] <= 1.03504f) { // tcp.srcport <= 1.04
                                    *out_class_idx = 8; // Password
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[25] <= 0.09905f) { // tcp.len <= 0.10
                                        *out_class_idx = 8; // Password
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 13; // Vulnerability_scanner
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            }
                        } else {
                            if (features[22] <= 0.61872f) { // tcp.dstport <= 0.62
                                *out_class_idx = 13; // Vulnerability_scanner
                                *out_anomaly_score = 0.7500f;
                                return 1;
                            } else {
                                if (features[15] <= -0.38191f) { // tcp.ack <= -0.38
                                    *out_class_idx = 14; // XSS
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    *out_class_idx = 13; // Vulnerability_scanner
                                    *out_anomaly_score = 0.7500f;
                                    return 1;
                                }
                            }
                        }
                    } else {
                        if (features[28] <= -0.26897f) { // tcp.seq <= -0.27
                            if (features[15] <= -0.38099f) { // tcp.ack <= -0.38
                                if (features[22] <= 1.45692f) { // tcp.dstport <= 1.46
                                    *out_class_idx = 13; // Vulnerability_scanner
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
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
                        } else {
                            *out_class_idx = 13; // Vulnerability_scanner
                            *out_anomaly_score = 1.0000f;
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
            if (features[33] <= -0.08897f) { // dns.qry.name <= -0.09
                *out_class_idx = 4; // DDoS_UDP
                *out_anomaly_score = 1.0000f;
                return 1;
            } else {
                if (features[33] <= 1.23492f) { // dns.qry.name <= 1.23
                    *out_class_idx = 4; // DDoS_UDP
                    *out_anomaly_score = 0.7500f;
                    return 1;
                } else {
                    *out_class_idx = 4; // DDoS_UDP
                    *out_anomaly_score = 1.0000f;
                    return 1;
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
