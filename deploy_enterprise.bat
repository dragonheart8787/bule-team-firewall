@echo off
echo ========================================
echo 企業級 WAF 防護系統部署腳本
echo ========================================

echo.
echo 1. 檢查系統狀態...
echo.

REM 檢查 Python 是否安裝
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 錯誤: 未找到 Python，請先安裝 Python 3.11+
    pause
    exit /b 1
)

REM 檢查 Docker 是否運行
docker version >nul 2>&1
if %errorlevel% neq 0 (
    echo 警告: Docker 未運行，將使用 Python 直接運行模式
    set USE_DOCKER=false
) else (
    echo Docker 已運行，將使用容器化部署
    set USE_DOCKER=true
)

echo.
echo 2. 安裝 Python 依賴...
pip install -r requirements.txt

echo.
echo 3. 生成 SSL 憑證...
python create_ssl_cert.py

echo.
echo 4. 啟動服務...

if "%USE_DOCKER%"=="true" (
    echo 使用 Docker Compose 啟動高可用配置...
    docker-compose -f docker-compose.ha.yml up -d
    
    echo.
    echo 等待服務啟動...
    timeout /t 10 /nobreak >nul
    
    echo.
    echo 檢查服務狀態...
    docker-compose -f docker-compose.ha.yml ps
) else (
    echo 使用 Python 直接運行模式...
    start "Target App" cmd /c "python target_app.py"
    timeout /t 3 /nobreak >nul
    
    start "SIEM Engine" cmd /c "python siem_dashboards.py"
    timeout /t 3 /nobreak >nul
    
    start "WAF Proxy" cmd /c "python waf_proxy.py"
    timeout /t 5 /nobreak >nul
)

echo.
echo 5. 執行系統測試...
python test_enterprise_features.py

echo.
echo ========================================
echo 部署完成！
echo ========================================
echo.
echo 服務端點：
echo - 目標應用: http://localhost:5000
echo - SIEM 引擎: http://localhost:8001
echo - WAF 代理: http://localhost:8080
echo.

if "%USE_DOCKER%"=="true" (
    echo 高可用端點：
    echo - Nginx 負載均衡器: http://localhost:80
    echo - HTTPS 端點: https://localhost:443
    echo - Prometheus 監控: http://localhost:9090
    echo - Grafana 儀表板: http://localhost:3000
    echo.
    echo 管理命令：
    echo - 查看日誌: docker-compose -f docker-compose.ha.yml logs
    echo - 停止服務: docker-compose -f docker-compose.ha.yml down
    echo - 重啟服務: docker-compose -f docker-compose.ha.yml restart
) else (
    echo 管理命令：
    echo - 查看 WAF 指標: http://localhost:8080/metrics
    echo - 查看 SIEM 指標: http://localhost:8001/metrics
    echo - 管理封鎖名單: http://localhost:8080/api/blocklist
)

echo.
echo 按任意鍵退出...
pause >nul
