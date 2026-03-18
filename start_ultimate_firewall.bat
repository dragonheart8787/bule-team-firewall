@echo off
chcp 65001 >nul
echo.
echo 🛡️ 終極軍事級防火牆系統 - 完整防禦體系
echo ================================================
echo.
echo 正在啟動終極軍事級防火牆系統...
echo.

REM 檢查Python是否安裝
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 未找到Python，請先安裝Python 3.8或更高版本
    pause
    exit /b 1
)

REM 檢查依賴套件
echo 檢查依賴套件...
python -c "import psutil, requests, yaml, numpy, secrets" >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 缺少必要的依賴套件
    echo 正在安裝依賴套件...
    pip install psutil requests pyyaml numpy
    if errorlevel 1 (
        echo ❌ 依賴套件安裝失敗
        pause
        exit /b 1
    )
)

REM 啟動終極軍事級防火牆系統
echo ✅ 依賴套件檢查完成
echo 正在啟動終極軍事級防火牆系統...
echo.

python ultimate_military_firewall.py

if errorlevel 1 (
    echo.
    echo ❌ 終極軍事級防火牆系統啟動失敗
    pause
    exit /b 1
)

echo.
echo ✅ 終極軍事級防火牆系統已停止
pause




