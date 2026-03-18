@echo off
echo ========================================
echo 軍事級綜合安全系統啟動腳本
echo ========================================
echo.

echo 正在啟動軍事級綜合安全系統...
echo.

REM 檢查 Python 是否安裝
python --version >nul 2>&1
if errorlevel 1 (
    echo 錯誤: 未找到 Python，請先安裝 Python 3.7 或更高版本
    pause
    exit /b 1
)

REM 安裝依賴套件
echo 正在安裝依賴套件...
pip install -r requirements.txt

REM 啟動主系統
echo 正在啟動主系統...
python military_comprehensive_system.py

echo.
echo 系統已關閉
pause

