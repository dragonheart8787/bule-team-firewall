@echo off
echo 重啟改進的企業級 WAF 系統...

echo 停止現有服務...
taskkill /f /im python.exe 2>nul

echo 等待服務停止...
timeout /t 3 /nobreak >nul

echo 啟動改進的目標應用...
start "Target App" python target_app_high_performance.py

echo 等待目標應用啟動...
timeout /t 3 /nobreak >nul

echo 啟動 SIEM 引擎...
start "SIEM" python siem_dashboards.py

echo 等待 SIEM 啟動...
timeout /t 3 /nobreak >nul

echo 啟動 WAF 代理...
start "WAF" python waf_proxy_enterprise_fixed.py

echo 等待 WAF 啟動...
timeout /t 5 /nobreak >nul

echo 所有服務已重啟完成！
echo 正在執行改進測試...

python improved_test_suite.py

echo 測試完成！
pause



