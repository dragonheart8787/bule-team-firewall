@echo off
chcp 65001 >nul
echo.
echo ========================================
echo 重啟服務並運行深度測試
echo ========================================
echo.

REM 停止所有 Python 進程
echo [1/5] 停止所有現有 Python 進程...
taskkill /f /im python.exe >nul 2>&1
timeout /t 3 /nobreak >nul
echo      完成！
echo.

REM 啟動 Target App
echo [2/5] 啟動 Target App (Port 5000)...
start "Target App" cmd /k "cd /d %~dp0 && python target_app_high_performance.py"
timeout /t 4 /nobreak >nul
echo      完成！
echo.

REM 啟動 SIEM
echo [3/5] 啟動 SIEM Dashboard (Port 8001)...
start "SIEM Dashboard" cmd /k "cd /d %~dp0 && python siem_dashboards.py"
timeout /t 4 /nobreak >nul
echo      完成！
echo.

REM 啟動 WAF
echo [4/5] 啟動 WAF Proxy (Port 8080)...
start "WAF Proxy" cmd /k "cd /d %~dp0 && python waf_proxy_final_solution.py"
timeout /t 4 /nobreak >nul
echo      完成！
echo.

REM 等待服務就緒
echo [5/5] 等待服務就緒 (15 秒)...
timeout /t 15 /nobreak >nul
echo      完成！
echo.

REM 檢查服務狀態
echo ========================================
echo 檢查服務狀態...
echo ========================================
python check_services.py
if errorlevel 1 (
    echo.
    echo [警告] 部分服務可能未就緒，但繼續測試...
    timeout /t 3 /nobreak >nul
)

echo.
echo ========================================
echo 開始深度測試 (進階測試)
echo ========================================
echo.
echo 預計測試時間: 約 5 分鐘
echo.

python advanced_test_methods.py

echo.
echo ========================================
echo 測試完成！
echo ========================================
echo.
echo 查看最新測試報告：
python show_latest_results.py

echo.
pause


