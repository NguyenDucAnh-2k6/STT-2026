/**
 * ====================================================================
 * TINYML ON-DEVICE NETWORK ANOMALY DETECTION MODEL (AUTO-GENERATED)
 * Target: ESP32 / ESP32-S3 / ARM Cortex-M / Embedded Edge Gateways
 * ====================================================================
 * 
 * Features vector index:
 *   [0] arp.opcode_cur
 *   [1] arp.hw.size_cur
 *   [2] icmp.checksum_cur
 *   [3] icmp.seq_le_cur
 *   [4] icmp.transmit_timestamp_cur
 *   [5] icmp.unused_cur
 *   [6] http.file_data_cur
 *   [7] http.content_length_cur
 *   [8] http.request.uri.query_cur
 *   [9] http.request.method_cur
 *   [10] http.referer_cur
 *   [11] http.request.full_uri_cur
 *   [12] http.request.version_cur
 *   [13] http.response_cur
 *   [14] http.tls_port_cur
 *   [15] tcp.ack_cur
 *   [16] tcp.ack_raw_cur
 *   [17] tcp.checksum_cur
 *   [18] tcp.connection.fin_cur
 *   [19] tcp.connection.rst_cur
 *   [20] tcp.connection.syn_cur
 *   [21] tcp.connection.synack_cur
 *   [22] tcp.dstport_cur
 *   [23] tcp.flags_cur
 *   [24] tcp.flags.ack_cur
 *   [25] tcp.len_cur
 *   [26] tcp.options_cur
 *   [27] tcp.payload_cur
 *   [28] tcp.seq_cur
 *   [29] tcp.srcport_cur
 *   [30] udp.port_cur
 *   [31] udp.stream_cur
 *   [32] udp.time_delta_cur
 *   [33] dns.qry.name_cur
 *   [34] dns.qry.name.len_cur
 *   [35] dns.qry.qu_cur
 *   [36] dns.qry.type_cur
 *   [37] dns.retransmission_cur
 *   [38] dns.retransmit_request_cur
 *   [39] dns.retransmit_request_in_cur
 *   [40] mqtt.conack.flags_cur
 *   [41] mqtt.conflag.cleansess_cur
 *   [42] mqtt.conflags_cur
 *   [43] mqtt.hdrflags_cur
 *   [44] mqtt.len_cur
 *   [45] mqtt.msg_decoded_as_cur
 *   [46] mqtt.msg_cur
 *   [47] mqtt.msgtype_cur
 *   [48] mqtt.proto_len_cur
 *   [49] mqtt.protoname_cur
 *   [50] mqtt.topic_cur
 *   [51] mqtt.topic_len_cur
 *   [52] mqtt.ver_cur
 *   [53] mbtcp.len_cur
 *   [54] mbtcp.trans_id_cur
 *   [55] mbtcp.unit_id_cur
 *   [56] arp.opcode_mean
 *   [57] arp.hw.size_mean
 *   [58] icmp.checksum_mean
 *   [59] icmp.seq_le_mean
 *   [60] icmp.transmit_timestamp_mean
 *   [61] icmp.unused_mean
 *   [62] http.file_data_mean
 *   [63] http.content_length_mean
 *   [64] http.request.uri.query_mean
 *   [65] http.request.method_mean
 *   [66] http.referer_mean
 *   [67] http.request.full_uri_mean
 *   [68] http.request.version_mean
 *   [69] http.response_mean
 *   [70] http.tls_port_mean
 *   [71] tcp.ack_mean
 *   [72] tcp.ack_raw_mean
 *   [73] tcp.checksum_mean
 *   [74] tcp.connection.fin_mean
 *   [75] tcp.connection.rst_mean
 *   [76] tcp.connection.syn_mean
 *   [77] tcp.connection.synack_mean
 *   [78] tcp.dstport_mean
 *   [79] tcp.flags_mean
 *   [80] tcp.flags.ack_mean
 *   [81] tcp.len_mean
 *   [82] tcp.options_mean
 *   [83] tcp.payload_mean
 *   [84] tcp.seq_mean
 *   [85] tcp.srcport_mean
 *   [86] udp.port_mean
 *   [87] udp.stream_mean
 *   [88] udp.time_delta_mean
 *   [89] dns.qry.name_mean
 *   [90] dns.qry.name.len_mean
 *   [91] dns.qry.qu_mean
 *   [92] dns.qry.type_mean
 *   [93] dns.retransmission_mean
 *   [94] dns.retransmit_request_mean
 *   [95] dns.retransmit_request_in_mean
 *   [96] mqtt.conack.flags_mean
 *   [97] mqtt.conflag.cleansess_mean
 *   [98] mqtt.conflags_mean
 *   [99] mqtt.hdrflags_mean
 *   [100] mqtt.len_mean
 *   [101] mqtt.msg_decoded_as_mean
 *   [102] mqtt.msg_mean
 *   [103] mqtt.msgtype_mean
 *   [104] mqtt.proto_len_mean
 *   [105] mqtt.protoname_mean
 *   [106] mqtt.topic_mean
 *   [107] mqtt.topic_len_mean
 *   [108] mqtt.ver_mean
 *   [109] mbtcp.len_mean
 *   [110] mbtcp.trans_id_mean
 *   [111] mbtcp.unit_id_mean
 *   [112] arp.opcode_std
 *   [113] arp.hw.size_std
 *   [114] icmp.checksum_std
 *   [115] icmp.seq_le_std
 *   [116] icmp.transmit_timestamp_std
 *   [117] icmp.unused_std
 *   [118] http.file_data_std
 *   [119] http.content_length_std
 *   [120] http.request.uri.query_std
 *   [121] http.request.method_std
 *   [122] http.referer_std
 *   [123] http.request.full_uri_std
 *   [124] http.request.version_std
 *   [125] http.response_std
 *   [126] http.tls_port_std
 *   [127] tcp.ack_std
 *   [128] tcp.ack_raw_std
 *   [129] tcp.checksum_std
 *   [130] tcp.connection.fin_std
 *   [131] tcp.connection.rst_std
 *   [132] tcp.connection.syn_std
 *   [133] tcp.connection.synack_std
 *   [134] tcp.dstport_std
 *   [135] tcp.flags_std
 *   [136] tcp.flags.ack_std
 *   [137] tcp.len_std
 *   [138] tcp.options_std
 *   [139] tcp.payload_std
 *   [140] tcp.seq_std
 *   [141] tcp.srcport_std
 *   [142] udp.port_std
 *   [143] udp.stream_std
 *   [144] udp.time_delta_std
 *   [145] dns.qry.name_std
 *   [146] dns.qry.name.len_std
 *   [147] dns.qry.qu_std
 *   [148] dns.qry.type_std
 *   [149] dns.retransmission_std
 *   [150] dns.retransmit_request_std
 *   [151] dns.retransmit_request_in_std
 *   [152] mqtt.conack.flags_std
 *   [153] mqtt.conflag.cleansess_std
 *   [154] mqtt.conflags_std
 *   [155] mqtt.hdrflags_std
 *   [156] mqtt.len_std
 *   [157] mqtt.msg_decoded_as_std
 *   [158] mqtt.msg_std
 *   [159] mqtt.msgtype_std
 *   [160] mqtt.proto_len_std
 *   [161] mqtt.protoname_std
 *   [162] mqtt.topic_std
 *   [163] mqtt.topic_len_std
 *   [164] mqtt.ver_std
 *   [165] mbtcp.len_std
 *   [166] mbtcp.trans_id_std
 *   [167] mbtcp.unit_id_std
 *   [168] arp.opcode_d_step
 *   [169] arp.hw.size_d_step
 *   [170] icmp.checksum_d_step
 *   [171] icmp.seq_le_d_step
 *   [172] icmp.transmit_timestamp_d_step
 *   [173] icmp.unused_d_step
 *   [174] http.file_data_d_step
 *   [175] http.content_length_d_step
 *   [176] http.request.uri.query_d_step
 *   [177] http.request.method_d_step
 *   [178] http.referer_d_step
 *   [179] http.request.full_uri_d_step
 *   [180] http.request.version_d_step
 *   [181] http.response_d_step
 *   [182] http.tls_port_d_step
 *   [183] tcp.ack_d_step
 *   [184] tcp.ack_raw_d_step
 *   [185] tcp.checksum_d_step
 *   [186] tcp.connection.fin_d_step
 *   [187] tcp.connection.rst_d_step
 *   [188] tcp.connection.syn_d_step
 *   [189] tcp.connection.synack_d_step
 *   [190] tcp.dstport_d_step
 *   [191] tcp.flags_d_step
 *   [192] tcp.flags.ack_d_step
 *   [193] tcp.len_d_step
 *   [194] tcp.options_d_step
 *   [195] tcp.payload_d_step
 *   [196] tcp.seq_d_step
 *   [197] tcp.srcport_d_step
 *   [198] udp.port_d_step
 *   [199] udp.stream_d_step
 *   [200] udp.time_delta_d_step
 *   [201] dns.qry.name_d_step
 *   [202] dns.qry.name.len_d_step
 *   [203] dns.qry.qu_d_step
 *   [204] dns.qry.type_d_step
 *   [205] dns.retransmission_d_step
 *   [206] dns.retransmit_request_d_step
 *   [207] dns.retransmit_request_in_d_step
 *   [208] mqtt.conack.flags_d_step
 *   [209] mqtt.conflag.cleansess_d_step
 *   [210] mqtt.conflags_d_step
 *   [211] mqtt.hdrflags_d_step
 *   [212] mqtt.len_d_step
 *   [213] mqtt.msg_decoded_as_d_step
 *   [214] mqtt.msg_d_step
 *   [215] mqtt.msgtype_d_step
 *   [216] mqtt.proto_len_d_step
 *   [217] mqtt.protoname_d_step
 *   [218] mqtt.topic_d_step
 *   [219] mqtt.topic_len_d_step
 *   [220] mqtt.ver_d_step
 *   [221] mbtcp.len_d_step
 *   [222] mbtcp.trans_id_d_step
 *   [223] mbtcp.unit_id_d_step
 *   [224] arp.opcode_d_win
 *   [225] arp.hw.size_d_win
 *   [226] icmp.checksum_d_win
 *   [227] icmp.seq_le_d_win
 *   [228] icmp.transmit_timestamp_d_win
 *   [229] icmp.unused_d_win
 *   [230] http.file_data_d_win
 *   [231] http.content_length_d_win
 *   [232] http.request.uri.query_d_win
 *   [233] http.request.method_d_win
 *   [234] http.referer_d_win
 *   [235] http.request.full_uri_d_win
 *   [236] http.request.version_d_win
 *   [237] http.response_d_win
 *   [238] http.tls_port_d_win
 *   [239] tcp.ack_d_win
 *   [240] tcp.ack_raw_d_win
 *   [241] tcp.checksum_d_win
 *   [242] tcp.connection.fin_d_win
 *   [243] tcp.connection.rst_d_win
 *   [244] tcp.connection.syn_d_win
 *   [245] tcp.connection.synack_d_win
 *   [246] tcp.dstport_d_win
 *   [247] tcp.flags_d_win
 *   [248] tcp.flags.ack_d_win
 *   [249] tcp.len_d_win
 *   [250] tcp.options_d_win
 *   [251] tcp.payload_d_win
 *   [252] tcp.seq_d_win
 *   [253] tcp.srcport_d_win
 *   [254] udp.port_d_win
 *   [255] udp.stream_d_win
 *   [256] udp.time_delta_d_win
 *   [257] dns.qry.name_d_win
 *   [258] dns.qry.name.len_d_win
 *   [259] dns.qry.qu_d_win
 *   [260] dns.qry.type_d_win
 *   [261] dns.retransmission_d_win
 *   [262] dns.retransmit_request_d_win
 *   [263] dns.retransmit_request_in_d_win
 *   [264] mqtt.conack.flags_d_win
 *   [265] mqtt.conflag.cleansess_d_win
 *   [266] mqtt.conflags_d_win
 *   [267] mqtt.hdrflags_d_win
 *   [268] mqtt.len_d_win
 *   [269] mqtt.msg_decoded_as_d_win
 *   [270] mqtt.msg_d_win
 *   [271] mqtt.msgtype_d_win
 *   [272] mqtt.proto_len_d_win
 *   [273] mqtt.protoname_d_win
 *   [274] mqtt.topic_d_win
 *   [275] mqtt.topic_len_d_win
 *   [276] mqtt.ver_d_win
 *   [277] mbtcp.len_d_win
 *   [278] mbtcp.trans_id_d_win
 *   [279] mbtcp.unit_id_d_win
 *   [280] arp.opcode_ptp
 *   [281] arp.hw.size_ptp
 *   [282] icmp.checksum_ptp
 *   [283] icmp.seq_le_ptp
 *   [284] icmp.transmit_timestamp_ptp
 *   [285] icmp.unused_ptp
 *   [286] http.file_data_ptp
 *   [287] http.content_length_ptp
 *   [288] http.request.uri.query_ptp
 *   [289] http.request.method_ptp
 *   [290] http.referer_ptp
 *   [291] http.request.full_uri_ptp
 *   [292] http.request.version_ptp
 *   [293] http.response_ptp
 *   [294] http.tls_port_ptp
 *   [295] tcp.ack_ptp
 *   [296] tcp.ack_raw_ptp
 *   [297] tcp.checksum_ptp
 *   [298] tcp.connection.fin_ptp
 *   [299] tcp.connection.rst_ptp
 *   [300] tcp.connection.syn_ptp
 *   [301] tcp.connection.synack_ptp
 *   [302] tcp.dstport_ptp
 *   [303] tcp.flags_ptp
 *   [304] tcp.flags.ack_ptp
 *   [305] tcp.len_ptp
 *   [306] tcp.options_ptp
 *   [307] tcp.payload_ptp
 *   [308] tcp.seq_ptp
 *   [309] tcp.srcport_ptp
 *   [310] udp.port_ptp
 *   [311] udp.stream_ptp
 *   [312] udp.time_delta_ptp
 *   [313] dns.qry.name_ptp
 *   [314] dns.qry.name.len_ptp
 *   [315] dns.qry.qu_ptp
 *   [316] dns.qry.type_ptp
 *   [317] dns.retransmission_ptp
 *   [318] dns.retransmit_request_ptp
 *   [319] dns.retransmit_request_in_ptp
 *   [320] mqtt.conack.flags_ptp
 *   [321] mqtt.conflag.cleansess_ptp
 *   [322] mqtt.conflags_ptp
 *   [323] mqtt.hdrflags_ptp
 *   [324] mqtt.len_ptp
 *   [325] mqtt.msg_decoded_as_ptp
 *   [326] mqtt.msg_ptp
 *   [327] mqtt.msgtype_ptp
 *   [328] mqtt.proto_len_ptp
 *   [329] mqtt.protoname_ptp
 *   [330] mqtt.topic_ptp
 *   [331] mqtt.topic_len_ptp
 *   [332] mqtt.ver_ptp
 *   [333] mbtcp.len_ptp
 *   [334] mbtcp.trans_id_ptp
 *   [335] mbtcp.unit_id_ptp
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

        if (features[31] <= -0.28183f) { // udp.stream_cur <= -0.28
            if (features[3] <= -0.25925f) { // icmp.seq_le_cur <= -0.26
                if (features[7] <= -0.14850f) { // http.content_length_cur <= -0.15
                    if (features[27] <= 2.14057f) { // tcp.payload_cur <= 2.14
                        if (features[22] <= -0.66718f) { // tcp.dstport_cur <= -0.67
                            if (features[15] <= 1.37340f) { // tcp.ack_cur <= 1.37
                                if (features[29] <= 1.51053f) { // tcp.srcport_cur <= 1.51
                                    if (features[29] <= 0.51294f) { // tcp.srcport_cur <= 0.51
                                        if (features[29] <= 0.44648f) { // tcp.srcport_cur <= 0.45
                                            if (features[2] <= -0.07487f) { // icmp.checksum_cur <= -0.07
                                                if (features[29] <= -0.23746f) { // tcp.srcport_cur <= -0.24
                                                    if (features[81] <= 0.30215f) { // tcp.len_mean <= 0.30
                                                        if (features[58] <= -0.05283f) { // icmp.checksum_mean <= -0.05
                                                            if (features[253] <= -2.32883f) { // tcp.srcport_d_win <= -2.33
                                                                if (features[140] <= 0.05140f) { // tcp.seq_std <= 0.05
                                                                    *out_class_idx = 5; // Fingerprinting
                                                                    *out_anomaly_score = 0.6667f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[132] <= 1.05255f) { // tcp.connection.syn_std <= 1.05
                                                                        *out_class_idx = 6; // MITM
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 6; // MITM
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[73] <= 0.07296f) { // tcp.checksum_mean <= 0.07
                                                                    if (features[135] <= 1.12582f) { // tcp.flags_std <= 1.13
                                                                        *out_class_idx = 10; // Ransomware
                                                                        *out_anomaly_score = 0.8382f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 6; // MITM
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[112] <= 2.94632f) { // arp.opcode_std <= 2.95
                                                                        *out_class_idx = 10; // Ransomware
                                                                        *out_anomaly_score = 0.6316f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 9; // Port_Scanning
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            if (features[84] <= -0.27921f) { // tcp.seq_mean <= -0.28
                                                                if (features[134] <= 1.16848f) { // tcp.dstport_std <= 1.17
                                                                    if (features[189] <= -2.75114f) { // tcp.connection.synack_d_step <= -2.75
                                                                        *out_class_idx = 9; // Port_Scanning
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 6; // MITM
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[309] <= 2.24502f) { // tcp.srcport_ptp <= 2.25
                                                                    if (features[141] <= 0.80421f) { // tcp.srcport_std <= 0.80
                                                                        *out_class_idx = 9; // Port_Scanning
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 6; // MITM
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[252] <= -0.00001f) { // tcp.seq_d_win <= -0.00
                                                                        *out_class_idx = 9; // Port_Scanning
                                                                        *out_anomaly_score = 0.9286f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 9; // Port_Scanning
                                                                        *out_anomaly_score = 0.7222f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if (features[197] <= -2.15513f) { // tcp.srcport_d_step <= -2.16
                                                            *out_class_idx = 6; // MITM
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 6; // MITM
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[252] <= 0.00100f) { // tcp.seq_d_win <= 0.00
                                                        if (features[17] <= 1.66148f) { // tcp.checksum_cur <= 1.66
                                                            if (features[113] <= 1.79915f) { // arp.hw.size_std <= 1.80
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
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
                                                if (features[297] <= 2.11419f) { // tcp.checksum_ptp <= 2.11
                                                    *out_class_idx = 2; // DDoS_ICMP
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
                                                } else {
                                                    *out_class_idx = 5; // Fingerprinting
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                }
                                            }
                                        } else {
                                            if (features[28] <= -0.28179f) { // tcp.seq_cur <= -0.28
                                                if (features[193] <= 0.14356f) { // tcp.len_d_step <= 0.14
                                                    if (features[191] <= -2.14683f) { // tcp.flags_d_step <= -2.15
                                                        *out_class_idx = 1; // DDoS_HTTP
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[197] <= -1.05518f) { // tcp.srcport_d_step <= -1.06
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.6667f;
                                                            return 1;
                                                        } else {
                                                            if (features[185] <= -1.09701f) { // tcp.checksum_d_step <= -1.10
                                                                if (features[128] <= 0.87888f) { // tcp.ack_raw_std <= 0.88
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.8750f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
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
                                        if (features[29] <= 0.96858f) { // tcp.srcport_cur <= 0.97
                                            if (features[15] <= -0.37671f) { // tcp.ack_cur <= -0.38
                                                if (features[15] <= -0.37881f) { // tcp.ack_cur <= -0.38
                                                    if (features[25] <= 0.11683f) { // tcp.len_cur <= 0.12
                                                        if (features[23] <= 0.83170f) { // tcp.flags_cur <= 0.83
                                                            if (features[16] <= -0.45464f) { // tcp.ack_raw_cur <= -0.45
                                                                if (features[137] <= 0.09871f) { // tcp.len_std <= 0.10
                                                                    if (features[85] <= 0.17028f) { // tcp.srcport_mean <= 0.17
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.9828f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[309] <= 2.22378f) { // tcp.srcport_ptp <= 2.22
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.7326f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            } else {
                                                                if (features[252] <= 0.00001f) { // tcp.seq_d_win <= 0.00
                                                                    if (features[242] <= 2.16378f) { // tcp.connection.fin_d_win <= 2.16
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.7979f;
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
                                                            }
                                                        } else {
                                                            if (features[28] <= -0.28228f) { // tcp.seq_cur <= -0.28
                                                                if (features[25] <= 0.08401f) { // tcp.len_cur <= 0.08
                                                                    *out_class_idx = 8; // Password
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
                                                        }
                                                    } else {
                                                        if (features[309] <= 1.78097f) { // tcp.srcport_ptp <= 1.78
                                                            *out_class_idx = 1; // DDoS_HTTP
                                                            *out_anomaly_score = 0.7500f;
                                                            return 1;
                                                        } else {
                                                            *out_class_idx = 11; // SQL_injection
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[28] <= -0.27911f) { // tcp.seq_cur <= -0.28
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
                                            if (features[15] <= -0.37280f) { // tcp.ack_cur <= -0.37
                                                if (features[15] <= -0.37992f) { // tcp.ack_cur <= -0.38
                                                    if (features[28] <= -0.28263f) { // tcp.seq_cur <= -0.28
                                                        if (features[246] <= -1.36238f) { // tcp.dstport_d_win <= -1.36
                                                            if (features[80] <= 0.22605f) { // tcp.flags.ack_mean <= 0.23
                                                                if (features[25] <= -0.09274f) { // tcp.len_cur <= -0.09
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[75] <= 0.02268f) { // tcp.connection.rst_mean <= 0.02
                                                                    *out_class_idx = 13; // Vulnerability_scanner
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.6667f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[73] <= -0.33208f) { // tcp.checksum_mean <= -0.33
                                                                if (features[73] <= -0.64756f) { // tcp.checksum_mean <= -0.65
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[81] <= -0.00343f) { // tcp.len_mean <= -0.00
                                                                    if (features[197] <= -0.19180f) { // tcp.srcport_d_step <= -0.19
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.9333f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[119] <= 0.86358f) { // http.content_length_std <= 0.86
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.7143f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if (features[248] <= -1.04269f) { // tcp.flags.ack_d_win <= -1.04
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
                                                    if (features[28] <= -0.28170f) { // tcp.seq_cur <= -0.28
                                                        if (features[282] <= 5.84572f) { // icmp.checksum_ptp <= 5.85
                                                            if (features[141] <= 1.10573f) { // tcp.srcport_std <= 1.11
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
                                                        if (features[29] <= 1.21495f) { // tcp.srcport_cur <= 1.21
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
                                    if (features[15] <= -0.37869f) { // tcp.ack_cur <= -0.38
                                        if (features[239] <= 0.00007f) { // tcp.ack_d_win <= 0.00
                                            if (features[28] <= -0.28184f) { // tcp.seq_cur <= -0.28
                                                if (features[25] <= -0.02413f) { // tcp.len_cur <= -0.02
                                                    if (features[184] <= -1.09860f) { // tcp.ack_raw_d_step <= -1.10
                                                        if (features[74] <= -0.02856f) { // tcp.connection.fin_mean <= -0.03
                                                            if (features[131] <= 1.20278f) { // tcp.connection.rst_std <= 1.20
                                                                if (features[133] <= 1.65069f) { // tcp.connection.synack_std <= 1.65
                                                                    if (features[79] <= -0.39199f) { // tcp.flags_mean <= -0.39
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            if (features[81] <= -0.09997f) { // tcp.len_mean <= -0.10
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            } else {
                                                                if (features[29] <= 1.51952f) { // tcp.srcport_cur <= 1.52
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[190] <= -2.44531f) { // tcp.dstport_d_step <= -2.45
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.7500f;
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
                                                        if (features[73] <= 0.05312f) { // tcp.checksum_mean <= 0.05
                                                            if (features[129] <= 1.05935f) { // tcp.checksum_std <= 1.06
                                                                if (features[140] <= 1.34198f) { // tcp.seq_std <= 1.34
                                                                    if (features[197] <= 2.47884f) { // tcp.srcport_d_step <= 2.48
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8750f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.6667f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    if (features[127] <= 0.33475f) { // tcp.ack_std <= 0.33
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 0.8333f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
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
                                                } else {
                                                    if (features[134] <= 0.85607f) { // tcp.dstport_std <= 0.86
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
                                            if (features[196] <= 0.00081f) { // tcp.seq_d_step <= 0.00
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
                                        if (features[15] <= -0.37831f) { // tcp.ack_cur <= -0.38
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
                            if (features[29] <= -0.86240f) { // tcp.srcport_cur <= -0.86
                                if (features[22] <= -0.26761f) { // tcp.dstport_cur <= -0.27
                                    if (features[15] <= -0.37972f) { // tcp.ack_cur <= -0.38
                                        *out_class_idx = 9; // Port_Scanning
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        *out_class_idx = 3; // DDoS_TCP
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    }
                                } else {
                                    if (features[19] <= 1.39729f) { // tcp.connection.rst_cur <= 1.40
                                        if (features[15] <= -0.37904f) { // tcp.ack_cur <= -0.38
                                            if (features[22] <= 1.69051f) { // tcp.dstport_cur <= 1.69
                                                if (features[22] <= 0.70728f) { // tcp.dstport_cur <= 0.71
                                                    if (features[22] <= 0.62636f) { // tcp.dstport_cur <= 0.63
                                                        if (features[143] <= 1.42568f) { // udp.stream_std <= 1.43
                                                            if (features[134] <= 1.09886f) { // tcp.dstport_std <= 1.10
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            }
                                                        } else {
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    } else {
                                                        if (features[183] <= 0.00055f) { // tcp.ack_d_step <= 0.00
                                                            if (features[78] <= 0.58898f) { // tcp.dstport_mean <= 0.59
                                                                if (features[22] <= 0.68676f) { // tcp.dstport_cur <= 0.69
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    if (features[15] <= -0.37974f) { // tcp.ack_cur <= -0.38
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 12; // Uploading
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
                                                            *out_class_idx = 8; // Password
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        }
                                                    }
                                                } else {
                                                    if (features[245] <= 2.75114f) { // tcp.connection.synack_d_win <= 2.75
                                                        if (features[22] <= 1.53214f) { // tcp.dstport_cur <= 1.53
                                                            if (features[170] <= -1.04700f) { // icmp.checksum_d_step <= -1.05
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            } else {
                                                                if (features[15] <= -0.37992f) { // tcp.ack_cur <= -0.38
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 8; // Password
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[22] <= 1.56421f) { // tcp.dstport_cur <= 1.56
                                                                if (features[103] <= -0.08445f) { // mqtt.msgtype_mean <= -0.08
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 1; // DDoS_HTTP
                                                                    *out_anomaly_score = 0.7500f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        if (features[22] <= 1.15345f) { // tcp.dstport_cur <= 1.15
                                                            if (features[76] <= -0.07999f) { // tcp.connection.syn_mean <= -0.08
                                                                if (features[133] <= 2.20092f) { // tcp.connection.synack_std <= 2.20
                                                                    *out_class_idx = 11; // SQL_injection
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 11; // SQL_injection
                                                                    *out_anomaly_score = 0.8000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[141] <= 1.02678f) { // tcp.srcport_std <= 1.03
                                                                    if (features[297] <= 2.51563f) { // tcp.checksum_ptp <= 2.52
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.8846f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 11; // SQL_injection
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[140] <= 0.03796f) { // tcp.seq_std <= 0.04
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                if (features[302] <= 2.52323f) { // tcp.dstport_ptp <= 2.52
                                                                    if (features[297] <= 2.75840f) { // tcp.checksum_ptp <= 2.76
                                                                        *out_class_idx = 13; // Vulnerability_scanner
                                                                        *out_anomaly_score = 0.8750f;
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
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                if (features[28] <= -0.28126f) { // tcp.seq_cur <= -0.28
                                                    if (features[15] <= -0.37957f) { // tcp.ack_cur <= -0.38
                                                        if (features[302] <= 2.53624f) { // tcp.dstport_ptp <= 2.54
                                                            if (features[159] <= 0.74156f) { // mqtt.msgtype_std <= 0.74
                                                                if (features[283] <= 4.96937f) { // icmp.seq_le_ptp <= 4.97
                                                                    if (features[17] <= -1.02130f) { // tcp.checksum_cur <= -1.02
                                                                        *out_class_idx = 8; // Password
                                                                        *out_anomaly_score = 0.6667f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 14; // XSS
                                                                        *out_anomaly_score = 1.0000f;
                                                                        return 1;
                                                                    }
                                                                } else {
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 0.8000f;
                                                                    return 1;
                                                                }
                                                            } else {
                                                                if (features[22] <= 1.74425f) { // tcp.dstport_cur <= 1.74
                                                                    *out_class_idx = 12; // Uploading
                                                                    *out_anomaly_score = 1.0000f;
                                                                    return 1;
                                                                } else {
                                                                    *out_class_idx = 14; // XSS
                                                                    *out_anomaly_score = 0.8333f;
                                                                    return 1;
                                                                }
                                                            }
                                                        } else {
                                                            if (features[305] <= 0.37550f) { // tcp.len_ptp <= 0.38
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 0.8750f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 12; // Uploading
                                                                *out_anomaly_score = 0.7500f;
                                                                return 1;
                                                            }
                                                        }
                                                    } else {
                                                        if (features[15] <= -0.37954f) { // tcp.ack_cur <= -0.38
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[129] <= 0.81335f) { // tcp.checksum_std <= 0.81
                                                                *out_class_idx = 8; // Password
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 14; // XSS
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[183] <= 0.00071f) { // tcp.ack_d_step <= 0.00
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
                                            if (features[22] <= 1.16499f) { // tcp.dstport_cur <= 1.16
                                                if (features[22] <= 0.77690f) { // tcp.dstport_cur <= 0.78
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 1.0000f;
                                                    return 1;
                                                } else {
                                                    if (features[15] <= -0.37751f) { // tcp.ack_cur <= -0.38
                                                        if (features[137] <= 0.32732f) { // tcp.len_std <= 0.33
                                                            if (features[28] <= -0.28208f) { // tcp.seq_cur <= -0.28
                                                                if (features[23] <= 0.77803f) { // tcp.flags_cur <= 0.78
                                                                    if (features[15] <= -0.37877f) { // tcp.ack_cur <= -0.38
                                                                        *out_class_idx = 11; // SQL_injection
                                                                        *out_anomaly_score = 0.9667f;
                                                                        return 1;
                                                                    } else {
                                                                        *out_class_idx = 1; // DDoS_HTTP
                                                                        *out_anomaly_score = 0.8158f;
                                                                        return 1;
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
                                                if (features[22] <= 1.46078f) { // tcp.dstport_cur <= 1.46
                                                    if (features[22] <= 1.25737f) { // tcp.dstport_cur <= 1.26
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
                                        if (features[24] <= -0.29529f) { // tcp.flags.ack_cur <= -0.30
                                            if (features[196] <= 0.00117f) { // tcp.seq_d_step <= 0.00
                                                if (features[309] <= 1.76364f) { // tcp.srcport_ptp <= 1.76
                                                    *out_class_idx = 1; // DDoS_HTTP
                                                    *out_anomaly_score = 0.7500f;
                                                    return 1;
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
                                            *out_class_idx = 3; // DDoS_TCP
                                            *out_anomaly_score = 1.0000f;
                                            return 1;
                                        }
                                    }
                                }
                            } else {
                                if (features[22] <= -0.63367f) { // tcp.dstport_cur <= -0.63
                                    *out_class_idx = 7; // Normal
                                    *out_anomaly_score = 1.0000f;
                                    return 1;
                                } else {
                                    if (features[29] <= -0.80541f) { // tcp.srcport_cur <= -0.81
                                        *out_class_idx = 7; // Normal
                                        *out_anomaly_score = 1.0000f;
                                        return 1;
                                    } else {
                                        if (features[22] <= 1.77887f) { // tcp.dstport_cur <= 1.78
                                            if (features[29] <= 1.40008f) { // tcp.srcport_cur <= 1.40
                                                if (features[22] <= 1.58237f) { // tcp.dstport_cur <= 1.58
                                                    if (features[29] <= -0.75534f) { // tcp.srcport_cur <= -0.76
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        if (features[22] <= -0.58324f) { // tcp.dstport_cur <= -0.58
                                                            *out_class_idx = 12; // Uploading
                                                            *out_anomaly_score = 1.0000f;
                                                            return 1;
                                                        } else {
                                                            if (features[141] <= 0.58766f) { // tcp.srcport_std <= 0.59
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 0.8333f;
                                                                return 1;
                                                            } else {
                                                                *out_class_idx = 10; // Ransomware
                                                                *out_anomaly_score = 1.0000f;
                                                                return 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    if (features[71] <= -0.35856f) { // tcp.ack_mean <= -0.36
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
                                                if (features[22] <= -0.53014f) { // tcp.dstport_cur <= -0.53
                                                    if (features[22] <= -0.58324f) { // tcp.dstport_cur <= -0.58
                                                        *out_class_idx = 12; // Uploading
                                                        *out_anomaly_score = 1.0000f;
                                                        return 1;
                                                    } else {
                                                        *out_class_idx = 0; // Backdoor
                                                        *out_anomaly_score = 0.0000f;
                                                        return 0;
                                                    }
                                                } else {
                                                    if (features[187] <= 1.71826f) { // tcp.connection.rst_d_step <= 1.72
                                                        *out_class_idx = 7; // Normal
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
                                            if (features[22] <= 1.80775f) { // tcp.dstport_cur <= 1.81
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
                        if (features[20] <= 1.12293f) { // tcp.connection.syn_cur <= 1.12
                            *out_class_idx = 7; // Normal
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        } else {
                            *out_class_idx = 3; // DDoS_TCP
                            *out_anomaly_score = 1.0000f;
                            return 1;
                        }
                    }
                } else {
                    if (features[15] <= -0.37568f) { // tcp.ack_cur <= -0.38
                        if (features[25] <= 0.22198f) { // tcp.len_cur <= 0.22
                            if (features[29] <= 1.00120f) { // tcp.srcport_cur <= 1.00
                                *out_class_idx = 8; // Password
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[75] <= -0.14914f) { // tcp.connection.rst_mean <= -0.15
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
                            if (features[15] <= -0.37945f) { // tcp.ack_cur <= -0.38
                                *out_class_idx = 14; // XSS
                                *out_anomaly_score = 1.0000f;
                                return 1;
                            } else {
                                if (features[79] <= -0.13437f) { // tcp.flags_mean <= -0.13
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
