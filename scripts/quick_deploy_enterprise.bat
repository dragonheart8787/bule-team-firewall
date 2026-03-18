@echo off
chcp 65001 >nul
echo ============================================================
echo 企業級 WAF 防護系統 - 一鍵部署腳本
echo ============================================================
echo.

echo 正在檢查 Python 環境...
python --version
if %errorlevel% neq 0 (
    echo 錯誤: 未找到 Python，請先安裝 Python 3.8+
    pause
    exit /b 1
)

echo.
echo 正在檢查必要文件...
if not exist "waf_proxy_enterprise_fixed.py" (
    echo 錯誤: 未找到 waf_proxy_enterprise_fixed.py
    pause
    exit /b 1
)

if not exist "siem_dashboards.py" (
    echo 錯誤: 未找到 siem_dashboards.py
    pause
    exit /b 1
)

if not exist "target_app.py" (
    echo 錯誤: 未找到 target_app.py
    pause
    exit /b 1
)

echo ✅ 所有必要文件已找到

echo.
echo 正在安裝依賴...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo 警告: 依賴安裝可能不完整，但將繼續執行
)

echo.
echo 正在生成 SSL 憑證...
python create_ssl_cert.py
if %errorlevel% neq 0 (
    echo 警告: SSL 憑證生成失敗，但將繼續執行
)

echo.
echo 正在啟動服務...
echo 啟動目標應用 (端口 5000)...
start /B python target_app.py

echo 等待目標應用啟動...
timeout /t 3 /nobreak >nul

echo 啟動 SIEM 引擎 (端口 8001)...
start /B python siem_dashboards.py

echo 等待 SIEM 引擎啟動...
timeout /t 3 /nobreak >nul

echo 啟動 WAF 代理 (端口 8080)...
start /B python waf_proxy_enterprise_fixed.py

echo 等待 WAF 代理啟動...
timeout /t 3 /nobreak >nul

echo.
echo 正在檢查服務健康狀態...
python check_system_status.py
if %errorlevel% neq 0 (
    echo 警告: 服務健康檢查失敗，但將繼續執行
)

echo.
echo 正在執行企業級測試...
echo 1. 實戰級壓測...
python enterprise_load_test_advanced.py --users 50 --duration 30 --attacks
if %errorlevel% neq 0 (
    echo 警告: 壓測失敗
)

echo.
echo 2. HA 故障演練...
python ha_chaos_test_advanced.py --scenario 1
if %errorlevel% neq 0 (
    echo 警告: 故障演練失敗
)

echo.
echo 3. 規則治理測試...
python rule_governance_advanced.py --test 1
if %errorlevel% neq 0 (
    echo 警告: 規則治理測試失敗
)

echo.
echo 4. 安全基線檢查...
python security_baseline_advanced.py --action audit
if %errorlevel% neq 0 (
    echo 警告: 安全基線檢查失敗
)

echo.
echo 5. 驗收標準測試...
python enterprise_validation_criteria.py --test 1
if %errorlevel% neq 0 (
    echo 警告: 驗收標準測試失敗
)

echo.
echo ============================================================
echo 企業級 WAF 防護系統部署完成！
echo ============================================================
echo.
echo 系統端點:
echo - 目標應用: http://localhost:5000
echo - SIEM 引擎: http://localhost:8001
echo - WAF 代理: http://localhost:8080
echo - WAF 管理: http://localhost:8080/api/blocklist
echo.
echo 測試工具:
echo - 系統狀態檢查: python check_system_status.py
echo - 企業級壓測: python enterprise_load_test_advanced.py
echo - HA 故障演練: python ha_chaos_test_advanced.py
echo - 規則治理: python rule_governance_advanced.py
echo - 安全基線: python security_baseline_advanced.py
echo - 驗收標準: python enterprise_validation_criteria.py
echo.
echo 停止服務: 按 Ctrl+C 或運行 stop_services.bat
echo.
pause
