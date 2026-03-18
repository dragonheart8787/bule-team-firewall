@echo off
echo 🛡️ 軍事級進階防禦系統啟動中...
echo ========================================

REM 檢查 Python 是否安裝
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 未找到 Python，請先安裝 Python 3.8+
    pause
    exit /b 1
)

REM 檢查依賴是否安裝
echo 📦 檢查依賴套件...
pip show numpy >nul 2>&1
if errorlevel 1 (
    echo 📥 安裝 numpy...
    pip install numpy
)

pip show pandas >nul 2>&1
if errorlevel 1 (
    echo 📥 安裝 pandas...
    pip install pandas
)

pip show scikit-learn >nul 2>&1
if errorlevel 1 (
    echo 📥 安裝 scikit-learn...
    pip install scikit-learn
)

pip show requests >nul 2>&1
if errorlevel 1 (
    echo 📥 安裝 requests...
    pip install requests
)

echo ✅ 依賴檢查完成

REM 啟動系統
echo 🚀 啟動軍事級進階防禦系統...
python military_advanced_defense_system.py

echo.
echo 系統已關閉
pause

