@echo off
chcp 65001 >nul
echo.
echo ========================================
echo 最終驗證測試
echo ========================================
echo.

REM 檢查服務
echo [步驟 1/3] 檢查服務健康狀態...
python check_services.py
if errorlevel 1 (
    echo.
    echo [錯誤] 部分服務未運行！
    echo 請先執行: start_all_services.bat
    echo.
    pause
    exit /b 1
)

echo.
echo [步驟 2/3] 執行快速測試...
echo.
python quick_test_suite.py

echo.
echo [步驟 3/3] 執行進階測試...
echo.
python advanced_test_methods.py

echo.
echo ========================================
echo 測試完成！
echo ========================================
echo.
echo 查看最新測試結果：
dir /b /od QUICK_TEST_RESULTS_*.json ADVANCED_TEST_REPORT_*.json | findstr /r "^[A-Z]" | tail -2
echo.

pause



