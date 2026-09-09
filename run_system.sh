#!/usr/bin/env bash
# ==============================================================================
# Edge AI Network Anomaly Detection System - Unix/Linux/macOS/WSL Launcher (.sh)
# ==============================================================================
# Chi dan su dung:
#   1. Cap quyen thuc thi (neu can):
#        chmod +x run_system.sh
#   2. Chay mac dinh voi ESP32 Simulator:
#        ./run_system.sh
#   3. Chay bat luu luong mang THAT cua may tinh (khi chua co ESP32):
#        ./run_system.sh --probe host
#   4. Chay voi thiet bi ESP32 vat ly qua WiFi/MQTT:
#        ./run_system.sh --probe esp32
#   5. Chay voi Random Forest va huan luyen lai:
#        ./run_system.sh --classifier random_forest --retrain
#   6. Chay bat mang that kem mo hinh Gradient Boosting:
#        ./run_system.sh --probe host --classifier gradient_boosting
#   7. Xem toan bo danh sach cac flag ho tro:
#        ./run_system.sh --help
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================================"
echo "      EDGE AI NETWORK ANOMALY DETECTION SYSTEM - UNIX LAUNCHER"
echo "============================================================================"
echo ""

# Xac dinh trinh thuc thi Python
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[LOI] Khong tim thay Python! Vui long cai dat Python 3.10+."
    exit 1
fi

# Kiem tra moi truong ao virtualenv neu ton tai
if [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    echo "[Launcher] Kich hoat moi truong ao: venv"
    source "$SCRIPT_DIR/venv/bin/activate"
elif [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    echo "[Launcher] Kich hoat moi truong ao: .venv"
    source "$SCRIPT_DIR/.venv/bin/activate"
fi

# Chuyen tiep toan bo doi so dong lenh vao run_system.py
exec "$PYTHON_BIN" "$SCRIPT_DIR/run_system.py" "$@"
