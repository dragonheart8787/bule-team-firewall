@echo off
echo ========================================
echo 新的測試報告和測試方法部署
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

echo 啟動 WAF 代理（最終解決方案版）...
start "WAF Final Solution" python waf_proxy_final_solution.py
timeout /t 3 /nobreak >nul

echo 等待服務啟動...
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo 運行快速測試套件
echo ========================================
python quick_test_suite.py

echo.
echo ========================================
echo 運行高級測試方法
echo ========================================
python advanced_test_methods.py

echo.
echo ========================================
echo 生成新的測試報告
echo ========================================
python new_test_report_generator.py

echo.
echo 所有測試完成！按任意鍵退出...
pause >nul




