@echo off
rem ==============================================================================
rem Edge AI Network Anomaly Detection System - Windows Launcher (.bat)
rem ==============================================================================
rem Chi dan su dung:
rem   1. Chay mac dinh (Host PC Live Sniffer bat luu luong mang that cua may tinh):
rem        run_system.bat
rem   2. Chay kem bo ban goi tin doc hai mang that (Dieu khien on-demand tu Web UI):
rem        run_system.bat --attack-sim
rem   3. Chay voi thiet bi ESP32 vat ly qua WiFi/MQTT (Promiscuous Mode):
rem        run_system.bat --probe esp32
rem   4. Chay ESP32 kem ban goi tin mang that:
rem        run_system.bat --probe esp32 --attack-sim
rem   5. 1-Click tu dong build va nap code cho ESP32 qua CLI (khong can mo Arduino IDE):
rem        run_system.bat --probe esp32 --attack-sim --flash
rem   6. Xem toan bo danh sach cac flag ho tro:
rem        run_system.bat --help
rem
rem Luu y: Huan luyen mo hinh Machine Learning da duoc tach rieng tai train.py:
rem        python ml_engine/train.py --classifier decision_tree
rem ==============================================================================

setlocal enabledelayedexpansion

title Edge AI Network Security System

echo ============================================================================
echo      EDGE AI NETWORK ANOMALY DETECTION SYSTEM - WINDOWS LAUNCHER
echo ============================================================================
echo.

rem Kiem tra Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [LOI] Khong tim thay Python trong PATH he thong!
    echo Vui long cai dat Python 3.10+ tu https://www.python.org va tick 'Add Python to PATH'.
    pause
    exit /b 1
)

rem Kiem tra moi truong ao neu co
if exist "venv\Scripts\activate.bat" (
    echo [Launcher] Kich hoat moi truong ao: venv
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo [Launcher] Kich hoat moi truong ao: .venv
    call .venv\Scripts\activate.bat
)

rem Chuyen tiep toan bo tham so dong lenh vao run_system.py
python "%~dp0run_system.py" %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo [Launcher] Tien trinh ket thuc voi ma loi: %ERRORLEVEL%
)

endlocal
