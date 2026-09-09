@echo off
rem ==============================================================================
rem Edge AI Network Anomaly Detection System - Windows Launcher (.bat)
rem ==============================================================================
rem Chi dan su dung:
rem   1. Chay mac dinh voi ESP32 Simulator:
rem        run_system.bat
rem   2. Chay bat luu luong mang THAT cua may tinh (khi chua co ESP32):
rem        run_system.bat --probe host
rem   3. Chay voi thiet bi ESP32 vat ly qua WiFi/MQTT:
rem        run_system.bat --probe esp32
rem   4. Chay voi Random Forest va huan luyen lai:
rem        run_system.bat --classifier random_forest --retrain
rem   5. Chay bat mang that kem mo hinh Gradient Boosting:
rem        run_system.bat --probe host --classifier gradient_boosting
rem   6. Xem toan bo danh sach cac flag ho tro:
rem        run_system.bat --help
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
