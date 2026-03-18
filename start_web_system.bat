@echo off
chcp 65001 >nul
cls
echo.
echo ========================================
echo 國防等級 Web 安全管理系統
echo Defense-Grade Web Security System
echo ========================================
echo.
echo 系統特性:
echo   [x] Web UI 介面
echo   [x] 密碼輸入框 (隱藏顯示)
echo   [x] 中央伺服器資料傳輸
echo   [x] 中間層攻擊防護
echo   [x] DDoS 防禦
echo   [x] CSRF 保護
echo   [x] Session 安全管理
echo   [x] 即時攻擊監控
echo.
echo 預設帳號:
echo   管理員: admin / Admin@2025
echo   用戶:   user  / User@2025
echo.
echo 啟動後請開啟瀏覽器訪問:
echo   http://127.0.0.1:5000
echo.
echo ========================================
echo.
pause

echo 正在啟動 Web 伺服器...
echo.

python secure_web_system.py

pause


