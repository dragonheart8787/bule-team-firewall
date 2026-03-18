@echo off
echo 啟動企業級 WAF 防護系統...

echo.
echo 1. 啟動目標應用 (端口 5000)...
start "Target App" cmd /c "python target_app.py"

timeout /t 3 /nobreak >nul

echo.
echo 2. 啟動 SIEM 引擎 (端口 8001)...
start "SIEM Engine" cmd /c "python siem_dashboards.py"

timeout /t 3 /nobreak >nul

echo.
echo 3. 啟動 WAF 代理 (端口 8080)...
start "WAF Proxy" cmd /c "python waf_proxy.py"

timeout /t 5 /nobreak >nul

echo.
echo 系統啟動完成！
echo.
echo 服務端點：
echo - 目標應用: http://localhost:5000
echo - SIEM 引擎: http://localhost:8001
echo - WAF 代理: http://localhost:8080
echo.
echo 管理端點：
echo - WAF 健康檢查: http://localhost:8080/healthz
echo - SIEM 健康檢查: http://localhost:8001/healthz
echo - WAF 指標: http://localhost:8080/metrics
echo - SIEM 指標: http://localhost:8001/metrics
echo - 封鎖名單: http://localhost:8080/api/blocklist
echo.
echo 按任意鍵進行測試...
pause >nul

echo.
echo 執行系統測試...
python test_enterprise_features.py

echo.
echo 測試完成！按任意鍵退出...
pause >nul

