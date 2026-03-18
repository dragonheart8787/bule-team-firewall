@echo off
chcp 65001 >nul
echo.
echo ========================================
echo 國防等級安全管理系統
echo Defense-Grade Secure Management System
echo ========================================
echo.
echo 系統特性:
echo   [x] 密碼保護 (PBKDF2-HMAC-SHA256)
echo   [x] 角色權限 (Admin / User)
echo   [x] APT 防護 (高級持續性威脅)
echo   [x] DDoS 防禦 (分散式阻斷服務)
echo   [x] 入侵檢測 (IDS/IPS)
echo   [x] 攻擊者追蹤 (IP + 行為記錄)
echo   [x] 審計日誌 (完整操作記錄)
echo.
echo 預設帳號:
echo   管理員: admin / Admin@2025
echo   用戶:   user  / User@2025
echo.
echo ========================================
echo.
pause

python secure_management_system.py

pause


