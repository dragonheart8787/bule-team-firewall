@echo off
echo ========================================
echo 終極版企業級 WAF 系統部署
echo ========================================

echo 停止現有服務...
taskkill /f /im python.exe 2>nul
timeout /t 2 /nobreak >nul

echo 啟動目標應用（高性能版）...
start "Target App" python target_app_high_performance.py
timeout /t 3 /nobreak >nul

echo 啟動 SIEM 系統...
start "SIEM" python siem_dashboards.py
timeout /t 5 /nobreak >nul

echo 啟動 WAF 代理（終極版）...
start "WAF Ultimate" python waf_proxy_ultimate.py
timeout /t 3 /nobreak >nul

echo 等待服務啟動...
timeout /t 5 /nobreak >nul

echo 運行終極版測試...
python test_ultimate_system.py

echo.
echo 部署完成！按任意鍵退出...
pause >nul




