@echo off
echo ========================================
echo 企業級 WAF 系統快速啟動
echo ========================================

echo.
echo 1. 檢查並安裝依賴...
pip install -r requirements.txt --quiet

echo.
echo 2. 生成 SSL 憑證...
python create_ssl_cert.py

echo.
echo 3. 啟動服務（背景運行）...
echo 啟動目標應用...
start /B python target_app.py > target_app.log 2>&1
timeout /t 2 /nobreak >nul

echo 啟動 SIEM 引擎...
start /B python siem_dashboards.py > siem_engine.log 2>&1
timeout /t 2 /nobreak >nul

echo 啟動 WAF 代理...
start /B python waf_proxy.py > waf_proxy.log 2>&1
timeout /t 3 /nobreak >nul

echo.
echo 4. 檢查服務狀態...
timeout /t 2 /nobreak >nul
python check_system_status.py

echo.
echo ========================================
echo 系統啟動完成！
echo ========================================
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
echo - 封鎖名單管理: http://localhost:8080/api/blocklist
echo.
echo 日誌檔案：
echo - target_app.log
echo - siem_engine.log  
echo - waf_proxy.log
echo.
echo 按任意鍵退出...
pause >nul
