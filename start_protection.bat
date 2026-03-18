@echo off
chcp 65001 >nul
echo.
echo 🛡️ 真實軍事級保護系統
echo ================================
echo.
echo 正在啟動真實軍事級保護系統...
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
python -c "import psutil, requests, yaml" >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 缺少必要的依賴套件
    echo 正在安裝依賴套件...
    pip install psutil requests pyyaml
    if errorlevel 1 (
        echo ❌ 依賴套件安裝失敗
        pause
        exit /b 1
    )
)

REM 啟動保護系統
echo ✅ 依賴套件檢查完成
echo 正在啟動真實軍事級保護系統...
echo.

REM 選擇啟動模式
echo 選擇啟動模式:
echo 1. 自動保護模式 (推薦)
echo 2. 互動模式
echo.
set /p choice="請選擇 (1-2): "

if "%choice%"=="1" (
    echo 啟動自動保護模式...
    python real_protection_system.py
) else if "%choice%"=="2" (
    echo 啟動互動模式...
    python real_protection_system.py --interactive
) else (
    echo 無效選擇，啟動自動保護模式...
    python real_protection_system.py
)

if errorlevel 1 (
    echo.
    echo ❌ 保護系統啟動失敗
    pause
    exit /b 1
)

echo.
echo ✅ 保護系統已停止
pause




