/**
 * ====================================================================
 * TINYML ON-DEVICE NETWORK ANOMALY DETECTION MODEL (AUTO-GENERATED)
 * Target: ESP32 / ESP32-S3 / ARM Cortex-M / Embedded Edge Gateways
 * ====================================================================
 * 
 * Features vector index:
 *   [0] packet_rate
 *   [1] byte_rate
 *   [2] avg_packet_size
 *   [3] syn_ratio
 *   [4] ack_ratio
 *   [5] udp_ratio
 *   [6] icmp_ratio
 *   [7] unique_dst_ports
 */

#ifndef TINYML_MODEL_H
#define TINYML_MODEL_H

#ifdef __cplusplus
extern "C" {
#endif

// Danh sach ten nhan tan cong
static const char* TINYML_LABEL_NAMES[] = {
    "Normal",
    "SYN_Flood",
    "Port_Scan",
    "Volumetric_DDoS",
    "Data_Exfiltration"
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

        if (features[7] <= -0.71469f) { // unique_dst_ports <= -0.71
            if (features[7] <= -0.78886f) { // unique_dst_ports <= -0.79
                if (features[5] <= -0.20350f) { // udp_ratio <= -0.20
                    if (features[5] <= -0.20591f) { // udp_ratio <= -0.21
                        if (features[6] <= 23.22926f) { // icmp_ratio <= 23.23
                            *out_class_idx = 3; // Volumetric_DDoS
                            *out_anomaly_score = 0.8017f;
                            return 1;
                        } else {
                            *out_class_idx = 1; // SYN_Flood
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        *out_class_idx = 0; // Normal
                        *out_anomaly_score = 0.0000f;
                        return 0;
                    }
                } else {
                    if (features[5] <= -0.19049f) { // udp_ratio <= -0.19
                        if (features[5] <= -0.19274f) { // udp_ratio <= -0.19
                            *out_class_idx = 3; // Volumetric_DDoS
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 0; // Normal
                            *out_anomaly_score = 0.3333f;
                            return 0;
                        }
                    } else {
                        if (features[5] <= -0.05862f) { // udp_ratio <= -0.06
                            if (features[5] <= -0.05967f) { // udp_ratio <= -0.06
                                *out_class_idx = 3; // Volumetric_DDoS
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                *out_class_idx = 0; // Normal
                                *out_anomaly_score = 0.5000f;
                                return 0;
                            }
                        } else {
                            *out_class_idx = 3; // Volumetric_DDoS
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    }
                }
            } else {
                if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                    *out_class_idx = 2; // Port_Scan
                    *out_anomaly_score = 0.7133f;
                    return 1;
                } else {
                    if (features[7] <= -0.77134f) { // unique_dst_ports <= -0.77
                        if (features[7] <= -0.77989f) { // unique_dst_ports <= -0.78
                            *out_class_idx = 4; // Data_Exfiltration
                            *out_anomaly_score = 0.6695f;
                            return 1;
                        } else {
                            *out_class_idx = 4; // Data_Exfiltration
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    } else {
                        if (features[7] <= -0.73429f) { // unique_dst_ports <= -0.73
                            *out_class_idx = 3; // Volumetric_DDoS
                            *out_anomaly_score = 0.8750f;
                            return 1;
                        } else {
                            if (features[7] <= -0.71846f) { // unique_dst_ports <= -0.72
                                if (features[7] <= -0.72510f) { // unique_dst_ports <= -0.73
                                    *out_class_idx = 2; // Port_Scan
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[7] <= -0.72437f) { // unique_dst_ports <= -0.72
                                        *out_class_idx = 2; // Port_Scan
                                        *out_anomaly_score = 0.7500f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 2; // Port_Scan
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            } else {
                                *out_class_idx = 2; // Port_Scan
                                *out_anomaly_score = 0.9091f;
                                return 1;
                            }
                        }
                    }
                }
            }
        } else {
            if (features[7] <= -0.71410f) { // unique_dst_ports <= -0.71
                *out_class_idx = 0; // Normal
                *out_anomaly_score = 0.0000f;
                return 0;
            } else {
                if (features[7] <= 1.28251f) { // unique_dst_ports <= 1.28
                    if (features[7] <= 1.15993f) { // unique_dst_ports <= 1.16
                        if (features[7] <= -0.32739f) { // unique_dst_ports <= -0.33
                            if (features[7] <= -0.61540f) { // unique_dst_ports <= -0.62
                                if (features[7] <= -0.61567f) { // unique_dst_ports <= -0.62
                                    if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                                        *out_class_idx = 1; // SYN_Flood
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        if (features[7] <= -0.65551f) { // unique_dst_ports <= -0.66
                                            if (features[7] <= -0.66960f) { // unique_dst_ports <= -0.67
                                                if (features[7] <= -0.67056f) { // unique_dst_ports <= -0.67
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9773f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[7] <= -0.65541f) { // unique_dst_ports <= -0.66
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[7] <= -0.63341f) { // unique_dst_ports <= -0.63
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9531f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9902f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                                        *out_class_idx = 1; // SYN_Flood
                                        *out_anomaly_score = 0.8294f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 4; // Data_Exfiltration
                                        *out_anomaly_score = 0.7725f;
                                        return 1;
                                    }
                                }
                            } else {
                                if (features[7] <= -0.55128f) { // unique_dst_ports <= -0.55
                                    if (features[7] <= -0.55156f) { // unique_dst_ports <= -0.55
                                        if (features[7] <= -0.58261f) { // unique_dst_ports <= -0.58
                                            if (features[7] <= -0.59764f) { // unique_dst_ports <= -0.60
                                                if (features[7] <= -0.59902f) { // unique_dst_ports <= -0.60
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9894f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= -0.58602f) { // unique_dst_ports <= -0.59
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9500f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= -0.58170f) { // unique_dst_ports <= -0.58
                                                *out_class_idx = 3; // Volumetric_DDoS
                                                *out_anomaly_score = 0.8333f;
                                                return 1;
                                            } else {
                                                if (features[7] <= -0.57593f) { // unique_dst_ports <= -0.58
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9167f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9779f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        *out_class_idx = 0; // Normal
                                        *out_anomaly_score = 0.0000f;
                                        return 0;
                                    }
                                } else {
                                    if (features[7] <= -0.34633f) { // unique_dst_ports <= -0.35
                                        if (features[7] <= -0.36930f) { // unique_dst_ports <= -0.37
                                            if (features[7] <= -0.41173f) { // unique_dst_ports <= -0.41
                                                if (features[7] <= -0.41299f) { // unique_dst_ports <= -0.41
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9775f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 3; // Volumetric_DDoS
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= -0.38595f) { // unique_dst_ports <= -0.39
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9643f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= -0.36612f) { // unique_dst_ports <= -0.37
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 0.7778f;
                                                return 1;
                                            } else {
                                                if (features[7] <= -0.34801f) { // unique_dst_ports <= -0.35
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9741f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.7857f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        *out_class_idx = 2; // Port_Scan
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            }
                        } else {
                            if (features[7] <= 1.06557f) { // unique_dst_ports <= 1.07
                                if (features[7] <= 0.70989f) { // unique_dst_ports <= 0.71
                                    if (features[7] <= 0.54980f) { // unique_dst_ports <= 0.55
                                        if (features[7] <= 0.53342f) { // unique_dst_ports <= 0.53
                                            if (features[7] <= 0.17320f) { // unique_dst_ports <= 0.17
                                                if (features[7] <= 0.15143f) { // unique_dst_ports <= 0.15
                                                    *out_class_idx = 3; // Volumetric_DDoS
                                                    *out_anomaly_score = 0.9700f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 3; // Volumetric_DDoS
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[7] <= 0.54117f) { // unique_dst_ports <= 0.54
                                                if (features[7] <= 0.53866f) { // unique_dst_ports <= 0.54
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7692f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.9032f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 0.54138f) { // unique_dst_ports <= 0.54
                                                    *out_class_idx = 3; // Volumetric_DDoS
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.8283f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        if (features[7] <= 0.63971f) { // unique_dst_ports <= 0.64
                                            if (features[7] <= 0.63894f) { // unique_dst_ports <= 0.64
                                                if (features[7] <= 0.60027f) { // unique_dst_ports <= 0.60
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.9591f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.7868f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[7] <= 0.64544f) { // unique_dst_ports <= 0.65
                                                *out_class_idx = 3; // Volumetric_DDoS
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[7] <= 0.69324f) { // unique_dst_ports <= 0.69
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.8649f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 3; // Volumetric_DDoS
                                                    *out_anomaly_score = 0.8529f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (features[7] <= 0.74007f) { // unique_dst_ports <= 0.74
                                        if (features[7] <= 0.71546f) { // unique_dst_ports <= 0.72
                                            if (features[7] <= 0.71212f) { // unique_dst_ports <= 0.71
                                                *out_class_idx = 4; // Data_Exfiltration
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.7778f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[7] <= 0.73924f) { // unique_dst_ports <= 0.74
                                                if (features[7] <= 0.73751f) { // unique_dst_ports <= 0.74
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7874f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 3; // Volumetric_DDoS
                                                *out_anomaly_score = 0.9000f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        if (features[7] <= 0.83862f) { // unique_dst_ports <= 0.84
                                            if (features[7] <= 0.83822f) { // unique_dst_ports <= 0.84
                                                if (features[7] <= 0.78920f) { // unique_dst_ports <= 0.79
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.8167f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.8242f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 0.7000f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[7] <= 1.00150f) { // unique_dst_ports <= 1.00
                                                if (features[7] <= 0.98992f) { // unique_dst_ports <= 0.99
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.8310f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.9405f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.02326f) { // unique_dst_ports <= 1.02
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7244f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.8178f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                if (features[7] <= 1.14843f) { // unique_dst_ports <= 1.15
                                    if (features[7] <= 1.14634f) { // unique_dst_ports <= 1.15
                                        if (features[7] <= 1.10010f) { // unique_dst_ports <= 1.10
                                            if (features[7] <= 1.09783f) { // unique_dst_ports <= 1.10
                                                if (features[7] <= 1.06624f) { // unique_dst_ports <= 1.07
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.8868f;
                                                    return 1;
                                                }
                                            } else {
                                                *out_class_idx = 3; // Volumetric_DDoS
                                                *out_anomaly_score = 0.8750f;
                                                return 1;
                                            }
                                        } else {
                                            if (features[7] <= 1.12955f) { // unique_dst_ports <= 1.13
                                                if (features[7] <= 1.10925f) { // unique_dst_ports <= 1.11
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.9524f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.13538f) { // unique_dst_ports <= 1.14
                                                    *out_class_idx = 3; // Volumetric_DDoS
                                                    *out_anomaly_score = 0.8571f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.9667f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        *out_class_idx = 3; // Volumetric_DDoS
                                        *out_anomaly_score = 0.8333f;
                                        return 1;
                                    }
                                } else {
                                    if (features[7] <= 1.15308f) { // unique_dst_ports <= 1.15
                                        *out_class_idx = 1; // SYN_Flood
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        if (features[7] <= 1.15450f) { // unique_dst_ports <= 1.15
                                            *out_class_idx = 1; // SYN_Flood
                                            *out_anomaly_score = 0.8000f;
                                            return 1;
                                        } else {
                                            if (features[7] <= 1.15932f) { // unique_dst_ports <= 1.16
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        if (features[7] <= 1.20090f) { // unique_dst_ports <= 1.20
                            if (features[7] <= 1.19509f) { // unique_dst_ports <= 1.20
                                if (features[7] <= 1.16406f) { // unique_dst_ports <= 1.16
                                    if (features[7] <= 1.16256f) { // unique_dst_ports <= 1.16
                                        if (features[7] <= 1.16009f) { // unique_dst_ports <= 1.16
                                            *out_class_idx = 2; // Port_Scan
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            if (features[7] <= 1.16042f) { // unique_dst_ports <= 1.16
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 0.9167f;
                                                return 1;
                                            } else {
                                                if (features[7] <= 1.16155f) { // unique_dst_ports <= 1.16
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.7778f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9167f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    } else {
                                        *out_class_idx = 2; // Port_Scan
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[7] <= 1.16734f) { // unique_dst_ports <= 1.17
                                        if (features[7] <= 1.16653f) { // unique_dst_ports <= 1.17
                                            if (features[7] <= 1.16487f) { // unique_dst_ports <= 1.16
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 0.8000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.8750f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 1; // SYN_Flood
                                            *out_anomaly_score = 0.8750f;
                                            return 1;
                                        }
                                    } else {
                                        if (features[7] <= 1.17245f) { // unique_dst_ports <= 1.17
                                            if (features[7] <= 1.16767f) { // unique_dst_ports <= 1.17
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            } else {
                                                if (features[7] <= 1.16795f) { // unique_dst_ports <= 1.17
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9226f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.17265f) { // unique_dst_ports <= 1.17
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 0.8333f;
                                                return 1;
                                            } else {
                                                if (features[7] <= 1.19493f) { // unique_dst_ports <= 1.19
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.8957f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                if (features[7] <= 1.19942f) { // unique_dst_ports <= 1.20
                                    if (features[7] <= 1.19793f) { // unique_dst_ports <= 1.20
                                        if (features[7] <= 1.19703f) { // unique_dst_ports <= 1.20
                                            if (features[7] <= 1.19645f) { // unique_dst_ports <= 1.20
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.8333f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 2; // Port_Scan
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    } else {
                                        *out_class_idx = 1; // SYN_Flood
                                        *out_anomaly_score = 0.8750f;
                                        return 1;
                                    }
                                } else {
                                    if (features[7] <= 1.20017f) { // unique_dst_ports <= 1.20
                                        *out_class_idx = 2; // Port_Scan
                                        *out_anomaly_score = 0.7500f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 2; // Port_Scan
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                }
                            }
                        } else {
                            if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                                if (features[7] <= 1.22825f) { // unique_dst_ports <= 1.23
                                    *out_class_idx = 0; // Normal
                                    *out_anomaly_score = 0.0000f;
                                    return 0;
                                } else {
                                    if (features[7] <= 1.23258f) { // unique_dst_ports <= 1.23
                                        *out_class_idx = 0; // Normal
                                        *out_anomaly_score = 0.5000f;
                                        return 0;
                                    } else {
                                        if (features[7] <= 1.25399f) { // unique_dst_ports <= 1.25
                                            if (features[7] <= 1.25190f) { // unique_dst_ports <= 1.25
                                                *out_class_idx = 0; // Normal
                                                *out_anomaly_score = 0.0000f;
                                                return 0;
                                            } else {
                                                *out_class_idx = 0; // Normal
                                                *out_anomaly_score = 0.5000f;
                                                return 0;
                                            }
                                        } else {
                                            *out_class_idx = 0; // Normal
                                            *out_anomaly_score = 0.0000f;
                                            return 0;
                                        }
                                    }
                                }
                            } else {
                                if (features[7] <= 1.27181f) { // unique_dst_ports <= 1.27
                                    if (features[7] <= 1.27001f) { // unique_dst_ports <= 1.27
                                        if (features[7] <= 1.26934f) { // unique_dst_ports <= 1.27
                                            if (features[7] <= 1.25048f) { // unique_dst_ports <= 1.25
                                                if (features[7] <= 1.24119f) { // unique_dst_ports <= 1.24
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.8889f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.8264f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.25053f) { // unique_dst_ports <= 1.25
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.5000f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.8725f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            *out_class_idx = 0; // Normal
                                            *out_anomaly_score = 0.5000f;
                                            return 0;
                                        }
                                    } else {
                                        if (features[7] <= 1.27096f) { // unique_dst_ports <= 1.27
                                            *out_class_idx = 2; // Port_Scan
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        } else {
                                            if (features[7] <= 1.27118f) { // unique_dst_ports <= 1.27
                                                *out_class_idx = 0; // Normal
                                                *out_anomaly_score = 0.3333f;
                                                return 0;
                                            } else {
                                                *out_class_idx = 2; // Port_Scan
                                                *out_anomaly_score = 0.9545f;
                                                return 1;
                                            }
                                        }
                                    }
                                } else {
                                    if (features[7] <= 1.28123f) { // unique_dst_ports <= 1.28
                                        if (features[7] <= 1.27447f) { // unique_dst_ports <= 1.27
                                            if (features[7] <= 1.27408f) { // unique_dst_ports <= 1.27
                                                if (features[7] <= 1.27390f) { // unique_dst_ports <= 1.27
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.7692f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.8000f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.27422f) { // unique_dst_ports <= 1.27
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9286f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.27918f) { // unique_dst_ports <= 1.28
                                                if (features[7] <= 1.27714f) { // unique_dst_ports <= 1.28
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.5789f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.2000f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[7] <= 1.27997f) { // unique_dst_ports <= 1.28
                                                    *out_class_idx = 2; // Port_Scan
                                                    *out_anomaly_score = 0.9375f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.5200f;
                                                    return 0;
                                                }
                                            }
                                        }
                                    } else {
                                        if (features[7] <= 1.28153f) { // unique_dst_ports <= 1.28
                                            *out_class_idx = 2; // Port_Scan
                                            *out_anomaly_score = 0.9545f;
                                            return 1;
                                        } else {
                                            *out_class_idx = 2; // Port_Scan
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if (features[7] <= 1.67800f) { // unique_dst_ports <= 1.68
                        if (features[7] <= 1.49078f) { // unique_dst_ports <= 1.49
                            if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                                *out_class_idx = 0; // Normal
                                *out_anomaly_score = 0.0000f;
                                return 0;
                            } else {
                                if (features[7] <= 1.45345f) { // unique_dst_ports <= 1.45
                                    if (features[7] <= 1.35957f) { // unique_dst_ports <= 1.36
                                        if (features[7] <= 1.35736f) { // unique_dst_ports <= 1.36
                                            if (features[7] <= 1.28739f) { // unique_dst_ports <= 1.29
                                                if (features[7] <= 1.28380f) { // unique_dst_ports <= 1.28
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.5000f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.0000f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[7] <= 1.29148f) { // unique_dst_ports <= 1.29
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.7609f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.3322f;
                                                    return 0;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.35743f) { // unique_dst_ports <= 1.36
                                                *out_class_idx = 4; // Data_Exfiltration
                                                *out_anomaly_score = 0.9000f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 0; // Normal
                                                *out_anomaly_score = 0.3636f;
                                                return 0;
                                            }
                                        }
                                    } else {
                                        if (features[7] <= 1.35998f) { // unique_dst_ports <= 1.36
                                            *out_class_idx = 3; // Volumetric_DDoS
                                            *out_anomaly_score = 0.8333f;
                                            return 1;
                                        } else {
                                            if (features[7] <= 1.43251f) { // unique_dst_ports <= 1.43
                                                if (features[7] <= 1.43012f) { // unique_dst_ports <= 1.43
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.3904f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.8333f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.43678f) { // unique_dst_ports <= 1.44
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.2000f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.4167f;
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (features[7] <= 1.47445f) { // unique_dst_ports <= 1.47
                                        if (features[7] <= 1.46951f) { // unique_dst_ports <= 1.47
                                            if (features[7] <= 1.45831f) { // unique_dst_ports <= 1.46
                                                if (features[7] <= 1.45377f) { // unique_dst_ports <= 1.45
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.4500f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[7] <= 1.45855f) { // unique_dst_ports <= 1.46
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.5789f;
                                                    return 0;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.47301f) { // unique_dst_ports <= 1.47
                                                if (features[7] <= 1.47265f) { // unique_dst_ports <= 1.47
                                                    *out_class_idx = 3; // Volumetric_DDoS
                                                    *out_anomaly_score = 0.9091f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.3333f;
                                                    return 0;
                                                }
                                            } else {
                                                *out_class_idx = 3; // Volumetric_DDoS
                                                *out_anomaly_score = 0.7857f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        if (features[7] <= 1.48713f) { // unique_dst_ports <= 1.49
                                            if (features[7] <= 1.47881f) { // unique_dst_ports <= 1.48
                                                if (features[7] <= 1.47761f) { // unique_dst_ports <= 1.48
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.2222f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.0000f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[7] <= 1.47915f) { // unique_dst_ports <= 1.48
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.9000f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.2121f;
                                                    return 0;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.48924f) { // unique_dst_ports <= 1.49
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.7273f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 0; // Normal
                                                *out_anomaly_score = 0.4444f;
                                                return 0;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            if (features[7] <= 1.49104f) { // unique_dst_ports <= 1.49
                                *out_class_idx = 4; // Data_Exfiltration
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[7] <= 1.59624f) { // unique_dst_ports <= 1.60
                                    if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                                        if (features[7] <= 1.58382f) { // unique_dst_ports <= 1.58
                                            *out_class_idx = 0; // Normal
                                            *out_anomaly_score = 0.0000f;
                                            return 0;
                                        } else {
                                            *out_class_idx = 0; // Normal
                                            *out_anomaly_score = 0.2000f;
                                            return 0;
                                        }
                                    } else {
                                        if (features[7] <= 1.58445f) { // unique_dst_ports <= 1.58
                                            if (features[7] <= 1.49161f) { // unique_dst_ports <= 1.49
                                                *out_class_idx = 4; // Data_Exfiltration
                                                *out_anomaly_score = 0.8000f;
                                                return 1;
                                            } else {
                                                if (features[7] <= 1.57858f) { // unique_dst_ports <= 1.58
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.3279f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.2857f;
                                                    return 0;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.58793f) { // unique_dst_ports <= 1.59
                                                if (features[7] <= 1.58597f) { // unique_dst_ports <= 1.59
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.4444f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.3000f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[7] <= 1.59488f) { // unique_dst_ports <= 1.59
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.5217f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.3333f;
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if (features[4] <= -0.43050f) { // ack_ratio <= -0.43
                                        if (features[7] <= 1.60373f) { // unique_dst_ports <= 1.60
                                            *out_class_idx = 0; // Normal
                                            *out_anomaly_score = 0.1250f;
                                            return 0;
                                        } else {
                                            if (features[7] <= 1.67624f) { // unique_dst_ports <= 1.68
                                                if (features[7] <= 1.65734f) { // unique_dst_ports <= 1.66
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7247f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.4667f;
                                                    return 0;
                                                }
                                            } else {
                                                *out_class_idx = 4; // Data_Exfiltration
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        }
                                    } else {
                                        if (features[7] <= 1.64837f) { // unique_dst_ports <= 1.65
                                            if (features[7] <= 1.62601f) { // unique_dst_ports <= 1.63
                                                if (features[7] <= 1.62536f) { // unique_dst_ports <= 1.63
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7749f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 0.8125f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.64801f) { // unique_dst_ports <= 1.65
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.8007f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 1; // SYN_Flood
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[7] <= 1.64872f) { // unique_dst_ports <= 1.65
                                                if (features[7] <= 1.64853f) { // unique_dst_ports <= 1.65
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.9987f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            } else {
                                                if (features[7] <= 1.65421f) { // unique_dst_ports <= 1.65
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7763f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 4; // Data_Exfiltration
                                                    *out_anomaly_score = 0.7633f;
                                                    return 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        if (features[7] <= 1.86389f) { // unique_dst_ports <= 1.86
                            if (features[7] <= 1.67837f) { // unique_dst_ports <= 1.68
                                *out_class_idx = 0; // Normal
                                *out_anomaly_score = 0.0000f;
                                return 0;
                            } else {
                                if (features[7] <= 1.68037f) { // unique_dst_ports <= 1.68
                                    if (features[7] <= 1.67885f) { // unique_dst_ports <= 1.68
                                        *out_class_idx = 0; // Normal
                                        *out_anomaly_score = 0.6667f;
                                        return 0;
                                    } else {
                                        if (features[7] <= 1.68029f) { // unique_dst_ports <= 1.68
                                            if (features[7] <= 1.67944f) { // unique_dst_ports <= 1.68
                                                *out_class_idx = 1; // SYN_Flood
                                                *out_anomaly_score = 0.7500f;
                                                return 1;
                                            } else {
                                                *out_class_idx = 4; // Data_Exfiltration
                                                *out_anomaly_score = 1.0000f;
                                                return 1;
                                            }
                                        } else {
                                            *out_class_idx = 0; // Normal
                                            *out_anomaly_score = 0.5000f;
                                            return 0;
                                        }
                                    }
                                } else {
                                    if (features[7] <= 1.82245f) { // unique_dst_ports <= 1.82
                                        if (features[7] <= 1.81873f) { // unique_dst_ports <= 1.82
                                            if (features[7] <= 1.74510f) { // unique_dst_ports <= 1.75
                                                if (features[7] <= 1.70630f) { // unique_dst_ports <= 1.71
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.0353f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.0000f;
                                                    return 0;
                                                }
                                            } else {
                                                if (features[7] <= 1.78051f) { // unique_dst_ports <= 1.78
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.1200f;
                                                    return 0;
                                                } else {
                                                    *out_class_idx = 0; // Normal
                                                    *out_anomaly_score = 0.0161f;
                                                    return 0;
                                                }
                                            }
                                        } else {
                                            *out_class_idx = 3; // Volumetric_DDoS
                                            *out_anomaly_score = 0.7500f;
                                            return 1;
                                        }
                                    } else {
                                        *out_class_idx = 0; // Normal
                                        *out_anomaly_score = 0.0000f;
                                        return 0;
                                    }
                                }
                            }
                        } else {
                            *out_class_idx = 1; // SYN_Flood
                            *out_anomaly_score = 1.0000f;
                            return 1;
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
    if (class_idx >= 0 && class_idx < 5) {
        return TINYML_LABEL_NAMES[class_idx];
    }
    return "Unknown";
}

#ifdef __cplusplus
}
#endif

#endif // TINYML_MODEL_H
