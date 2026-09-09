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

        if (features[0] <= 220.04303f) { // packet_rate <= 220.04
            if (features[4] <= 0.89998f) { // ack_ratio <= 0.90
                *out_class_idx = 0; // Normal
                *out_anomaly_score = 0.0000f;
                return 0;
            } else {
                *out_class_idx = 4; // Data_Exfiltration
                *out_anomaly_score = 1.0000f;
                return 1;
            }
        } else {
            if (features[1] <= 1864846.23438f) { // byte_rate <= 1864846.23
                if (features[5] <= 0.07524f) { // udp_ratio <= 0.08
                    if (features[3] <= 0.44005f) { // syn_ratio <= 0.44
                        *out_class_idx = 4; // Data_Exfiltration
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    } else {
                        *out_class_idx = 1; // SYN_Flood
                        *out_anomaly_score = 1.0000f;
                        return 1;
                    }
                } else {
                    *out_class_idx = 2; // Port_Scan
                    *out_anomaly_score = 1.0000f;
                    return 1;
                }
            } else {
                *out_class_idx = 3; // Volumetric_DDoS
                *out_anomaly_score = 1.0000f;
                return 1;
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
