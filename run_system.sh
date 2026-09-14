#!/usr/bin/env bash
# ==============================================================================
# Edge AI Network Anomaly Detection System - Unix/Linux/macOS/WSL Launcher (.sh)
# ==============================================================================
# Chi dan su dung:
#   1. Cap quyen thuc thi (neu can):
#        chmod +x run_system.sh
#   2. Chay mac dinh (Host PC Live Sniffer bat luu luong mang that cua may tinh):
#        ./run_system.sh
#   3. Chay kem bo ban goi tin doc hai mang that (Dieu khien on-demand tu Web UI):
#        ./run_system.sh --attack-sim
#   4. Chay voi thiet bi ESP32 vat ly qua WiFi/MQTT (Promiscuous Mode):
#        ./run_system.sh --probe esp32
#   5. Chay ESP32 kem ban goi tin mang that:
#        ./run_system.sh --probe esp32 --attack-sim
#   6. 1-Click tu dong build va nap code cho ESP32 qua CLI (khong can mo Arduino IDE GUI):
#        ./run_system.sh --probe esp32 --attack-sim --flash
#   7. Chi dinh cong Serial ro rang khi nap ESP32:
#        ./run_system.sh --flash --port /dev/ttyUSB0           # Tren Linux
#        ./run_system.sh --flash --port /dev/cu.usbserial-0001 # Tren macOS
#   8. Xem toan bo danh sach cac flag ho tro:
#        ./run_system.sh --help
#
# Luu y: Huan luyen mo hinh Machine Learning da duoc tach rieng tai train.py:
#        python3 ml_engine/train.py --classifier decision_tree
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================================"
echo "      EDGE AI NETWORK ANOMALY DETECTION SYSTEM - UNIX LAUNCHER"
echo "============================================================================"
echo ""

# Kiem tra va kich hoat moi truong ao virtualenv neu ton tai
if [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    echo "[Launcher] Kich hoat moi truong ao: venv"
    source "$SCRIPT_DIR/venv/bin/activate"
    PYTHON_BIN="python"
elif [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    echo "[Launcher] Kich hoat moi truong ao: .venv"
    source "$SCRIPT_DIR/.venv/bin/activate"
    PYTHON_BIN="python"
else
    # Xac dinh trinh thuc thi Python he thong
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="python"
    else
        echo "[LOI] Khong tim thay Python! Vui long cai dat Python 3.10+."
        exit 1
    fi
fi

# Chuyen tiep toan bo doi so dong lenh vao run_system.py
exec "$PYTHON_BIN" "$SCRIPT_DIR/run_system.py" "$@"
