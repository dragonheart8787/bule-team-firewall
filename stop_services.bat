@echo off
echo ========================================
echo 停止企業級 WAF 系統
echo ========================================

echo.
echo 正在停止所有服務...

REM 停止 Python 進程
taskkill /f /im python.exe >nul 2>&1

echo.
echo 清理完成！
echo.
echo 按任意鍵退出...
pause >nul
