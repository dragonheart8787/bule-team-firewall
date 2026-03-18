@echo off
chcp 65001 >nul
title 真實終極軍事防禦系統

echo.
echo ========================================
echo   真實終極軍事防禦系統啟動中...
echo   Real Ultimate Military Defense System
echo ========================================
echo.

REM 檢查Python是否安裝
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 未找到Python，請先安裝Python 3.8+
    pause
    exit /b 1
)

REM 檢查必要模組
echo 🔍 檢查系統依賴...
python -c "import yaml, threading, subprocess, hashlib, hmac, secrets" >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 缺少必要模組，正在安裝...
    pip install pyyaml pywin32
    if errorlevel 1 (
        echo ❌ 安裝依賴失敗
        pause
        exit /b 1
    )
)

REM 檢查配置文件
if not exist "real_ultimate_defense_config.yaml" (
    echo ❌ 錯誤: 未找到配置文件 real_ultimate_defense_config.yaml
    pause
    exit /b 1
)

REM 檢查防禦模組
echo 🔍 檢查防禦模組...
set missing_modules=0

if not exist "real_network_monitor.py" (
    echo ❌ 缺少: real_network_monitor.py
    set /a missing_modules+=1
)

if not exist "real_threat_detection.py" (
    echo ❌ 缺少: real_threat_detection.py
    set /a missing_modules+=1
)

if not exist "real_incident_response.py" (
    echo ❌ 缺少: real_incident_response.py
    set /a missing_modules+=1
)

if not exist "real_digital_forensics.py" (
    echo ❌ 缺少: real_digital_forensics.py
    set /a missing_modules+=1
)

if not exist "real_malware_analysis.py" (
    echo ❌ 缺少: real_malware_analysis.py
    set /a missing_modules+=1
)

if not exist "real_penetration_testing.py" (
    echo ❌ 缺少: real_penetration_testing.py
    set /a missing_modules+=1
)

if not exist "real_zero_trust_network_segmentation.py" (
    echo ❌ 缺少: real_zero_trust_network_segmentation.py
    set /a missing_modules+=1
)

if not exist "real_ai_ml_threat_hunting.py" (
    echo ❌ 缺少: real_ai_ml_threat_hunting.py
    set /a missing_modules+=1
)

if not exist "real_threat_intelligence_integration.py" (
    echo ❌ 缺少: real_threat_intelligence_integration.py
    set /a missing_modules+=1
)

if not exist "real_cloud_ot_iot_security.py" (
    echo ❌ 缺少: real_cloud_ot_iot_security.py
    set /a missing_modules+=1
)

if not exist "real_defense_automation_soar.py" (
    echo ❌ 缺少: real_defense_automation_soar.py
    set /a missing_modules+=1
)

if not exist "real_military_hardware_protection.py" (
    echo ❌ 缺少: real_military_hardware_protection.py
    set /a missing_modules+=1
)

if not exist "real_advanced_reporting_risk_quantification.py" (
    echo ❌ 缺少: real_advanced_reporting_risk_quantification.py
    set /a missing_modules+=1
)

if %missing_modules% gtr 0 (
    echo.
    echo ❌ 錯誤: 缺少 %missing_modules% 個防禦模組
    echo 請確保所有防禦模組文件都存在
    pause
    exit /b 1
)

echo ✅ 所有防禦模組檢查完成

REM 檢查 Suricata 和 Sysmon 是否已安裝
echo.
echo 🔍 檢查 Suricata 和 Sysmon...

suricata --version >nul 2>&1
if errorlevel 1 (
    echo ⚠️ 警告: 未找到 Suricata，建議執行 install_suricata_sysmon.bat
    set suricata_available=0
) else (
    echo ✅ Suricata 已安裝
    set suricata_available=1
)

sysmon -? >nul 2>&1
if errorlevel 1 (
    echo ⚠️ 警告: 未找到 Sysmon，建議執行 install_suricata_sysmon.bat
    set sysmon_available=0
) else (
    echo ✅ Sysmon 已安裝
    set sysmon_available=1
)

if %suricata_available%==0 (
    echo.
    echo 💡 提示: 要獲得完整威脅檢測能力，請先執行:
    echo    install_suricata_sysmon.bat
    echo.
    choice /C YN /M "是否要現在安裝 Suricata 和 Sysmon? (Y/N)"
    if errorlevel 2 goto skip_install
    if errorlevel 1 (
        echo 正在執行安裝...
        call install_suricata_sysmon.bat
        if errorlevel 1 (
            echo ❌ 安裝失敗，但系統仍可運行（部分功能受限）
        )
    )
)
:skip_install

REM 創建必要目錄
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "reports" mkdir reports
if not exist "rules" mkdir rules
if not exist "rules\yara" mkdir rules\yara
if not exist "certs" mkdir certs

echo.
echo 🛡️ 啟動真實終極軍事防禦系統...
echo.

REM 啟動防禦系統
python real_ultimate_military_defense_system.py

echo.
echo 系統已停止
pause
