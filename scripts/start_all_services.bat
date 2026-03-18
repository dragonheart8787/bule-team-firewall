@echo off
chcp 65001 >nul
echo ========================================
echo 啟動所有服務
echo ========================================
echo.

REM 停止現有進程
echo [1/4] 停止現有服務...
taskkill /f /im python.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo      完成！
echo.

REM 啟動 Target App
echo [2/4] 啟動 Target App (Port 5000)...
start "Target App" cmd /k "python target_app_high_performance.py"
timeout /t 3 /nobreak >nul
echo      完成！
echo.

REM 啟動 SIEM
echo [3/4] 啟動 SIEM Dashboard (Port 8001)...
start "SIEM Dashboard" cmd /k "python siem_dashboards.py"
timeout /t 3 /nobreak >nul
echo      完成！
echo.

REM 啟動 WAF
echo [4/4] 啟動 WAF Proxy (Port 8080)...
start "WAF Proxy" cmd /k "python waf_proxy_final_solution.py"
timeout /t 3 /nobreak >nul
echo      完成！
echo.

echo ========================================
echo 所有服務已啟動！
echo ========================================
echo.
echo 服務列表：
echo   - Target App:      http://localhost:5000
echo   - SIEM Dashboard:  http://localhost:8001
echo   - WAF Proxy:       http://localhost:8080
echo.
echo 等待 5 秒後開始測試...
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo 開始快速測試
echo ========================================
python quick_test_suite.py

pause



