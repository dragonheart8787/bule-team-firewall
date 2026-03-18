@echo off
chcp 65001 >nul
echo ============================================================
echo 停止企業級 WAF 防護系統服務
echo ============================================================
echo.

echo 正在停止 Python 服務...

echo 停止 WAF 代理...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *waf_proxy*" 2>nul
taskkill /F /IM python.exe /FI "COMMANDLINE eq *waf_proxy*" 2>nul

echo 停止 SIEM 引擎...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *siem*" 2>nul
taskkill /F /IM python.exe /FI "COMMANDLINE eq *siem*" 2>nul

echo 停止目標應用...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *target*" 2>nul
taskkill /F /IM python.exe /FI "COMMANDLINE eq *target*" 2>nul

echo 停止所有相關 Python 進程...
for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV ^| findstr /V "INFO:"') do (
    set pid=%%i
    set pid=!pid:"=!
    for /f "tokens=*" %%j in ('wmic process where "ProcessId=!pid!" get CommandLine /format:list ^| findstr "CommandLine"') do (
        set cmdline=%%j
        set cmdline=!cmdline:CommandLine=!
        echo !cmdline! | findstr /I "waf_proxy\|siem\|target" >nul
        if !errorlevel! equ 0 (
            echo 停止進程 !pid!
            taskkill /F /PID !pid! 2>nul
        )
    )
)

echo.
echo 正在檢查端口使用情況...
echo 檢查端口 5000 (目標應用)...
netstat -ano | findstr :5000
if %errorlevel% equ 0 (
    echo 端口 5000 仍在使用中
) else (
    echo ✅ 端口 5000 已釋放
)

echo 檢查端口 8001 (SIEM 引擎)...
netstat -ano | findstr :8001
if %errorlevel% equ 0 (
    echo 端口 8001 仍在使用中
) else (
    echo ✅ 端口 8001 已釋放
)

echo 檢查端口 8080 (WAF 代理)...
netstat -ano | findstr :8080
if %errorlevel% equ 0 (
    echo 端口 8080 仍在使用中
) else (
    echo ✅ 端口 8080 已釋放
)

echo.
echo 正在清理臨時文件...
if exist "*.log" del /Q *.log
if exist "*.tmp" del /Q *.tmp
if exist "waf_blocklist.json" del /Q waf_blocklist.json

echo.
echo ============================================================
echo 企業級 WAF 防護系統服務已停止
echo ============================================================
echo.
echo 所有服務已停止，端口已釋放，臨時文件已清理
echo.
pause
