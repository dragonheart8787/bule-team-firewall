@echo off
chcp 65001 >nul
cls
echo.
echo ========================================
echo 國防等級 Web 系統 - 完整部署和測試
echo ========================================
echo.

REM 停止所有現有服務
echo [1/5] 停止現有服務...
taskkill /f /im python.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo      完成！
echo.

REM 啟動中央伺服器
echo [2/5] 啟動中央伺服器 (Port 9000)...
start "Central Server" cmd /k "cd /d %~dp0 && python central_server.py"
timeout /t 4 /nobreak >nul
echo      完成！
echo.

REM 啟動 Web 系統
echo [3/5] 啟動 Web 安全系統 (Port 5000)...
start "Web System" cmd /k "cd /d %~dp0 && python secure_web_system.py"
timeout /t 4 /nobreak >nul
echo      完成！
echo.

REM 等待服務就緒
echo [4/5] 等待服務就緒 (10 秒)...
timeout /t 10 /nobreak >nul
echo      完成！
echo.

REM 開啟瀏覽器
echo [5/5] 開啟瀏覽器...
start http://127.0.0.1:5000
timeout /t 2 /nobreak >nul
echo      完成！
echo.

echo ========================================
echo 所有服務已啟動！
echo ========================================
echo.
echo 服務列表：
echo   - Web 系統:     http://127.0.0.1:5000
echo   - 中央伺服器:   http://127.0.0.1:9000
echo.
echo 預設帳號：
echo   管理員: admin / Admin@2025
echo   用戶:   user  / User@2025
echo.
echo ========================================
echo 按任意鍵開始測試...
echo ========================================
pause >nul

echo.
echo ========================================
echo 開始完整系統測試
echo ========================================
echo.

REM 運行完整測試
python full_system_test.py

echo.
echo ========================================
echo 開始攻擊測試
echo ========================================
echo.

REM 運行攻擊測試
python attack_test_suite.py

echo.
echo ========================================
echo 測試完成！
echo ========================================
echo.
echo 查看測試報告:
dir /b /od ATTACK_TEST_REPORT_*.json FULL_SYSTEM_TEST_*.json 2>nul | findstr /r "^[A-Z]"
echo.
echo Web 系統和中央伺服器仍在運行中
echo 可以在瀏覽器中繼續測試
echo.

pause


