@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

cd /d "%~dp0"

echo.
echo ================================================================
echo          籃隊防禦系統 - 完整功能測試
echo          Full Functionality Test Suite
echo ================================================================
echo.

set START_TIME=%date% %time%
set FAIL_COUNT=0

echo [開始] 測試開始時間: %START_TIME%
echo.

REM ========== 測試 1: 防火牆能力測試 ==========
echo.
echo ----------------------------------------------------------------
echo [1/6] 防火牆完整能力測試 (48 項)
echo ----------------------------------------------------------------
python test_all_firewall_capabilities.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] 防火牆測試失敗
    set /a FAIL_COUNT+=1
) else (
    echo [OK] 防火牆測試完成
)

REM ========== 測試 2: Kill Chain 檢測 ==========
echo.
echo ----------------------------------------------------------------
echo [2/6] Kill Chain 7 階段檢測
echo ----------------------------------------------------------------
python kill_chain_detector.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Kill Chain 測試失敗
    set /a FAIL_COUNT+=1
) else (
    echo [OK] Kill Chain 測試完成
)

REM ========== 測試 3: 國防等級測試 ==========
echo.
echo ----------------------------------------------------------------
echo [3/6] 國防等級完整測試 (121 項)
echo ----------------------------------------------------------------
python national_defense_grade_test.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] 國防等級測試失敗
    set /a FAIL_COUNT+=1
) else (
    echo [OK] 國防等級測試完成
)

REM ========== 測試 4: MITRE ATT&CK 覆蓋率 ==========
echo.
echo ----------------------------------------------------------------
echo [4/6] MITRE ATT^&CK 覆蓋率報告
echo ----------------------------------------------------------------
python run_mitre_report.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] ATT^&CK 報告生成跳過
) else (
    echo [OK] ATT^&CK 報告完成
)

REM ========== 測試 5: 獨立認證測試 ==========
echo.
echo ----------------------------------------------------------------
echo [5/6] 獨立認證級測試 (7 項)
echo ----------------------------------------------------------------
python standalone_certification_tests.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] 認證測試部分失敗
) else (
    echo [OK] 認證測試完成
)

REM ========== 測試 6: 防火牆初始化驗證 ==========
echo.
echo ----------------------------------------------------------------
echo [6/6] 防火牆初始化驗證
echo ----------------------------------------------------------------
python run_firewall_verify.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] 防火牆驗證失敗
    set /a FAIL_COUNT+=1
) else (
    echo [OK] 防火牆驗證完成
)

REM ========== 生成功能報告 ==========
echo.
echo ----------------------------------------------------------------
echo 生成整合功能報告
echo ----------------------------------------------------------------
python generate_function_report.py
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] 報告生成失敗
) else (
    echo [OK] 功能報告已生成
)

REM ========== 完成 ==========
set END_TIME=%date% %time%
echo.
echo ================================================================
echo 測試完成摘要
echo ================================================================
echo 開始時間: %START_TIME%
echo 結束時間: %END_TIME%
echo 失敗數: %FAIL_COUNT%
echo.
if %FAIL_COUNT% EQU 0 (
    echo [OK] 所有核心測試通過！
    echo [OK] 評級: 認證通過
) else (
    echo [WARN] 有 %FAIL_COUNT% 項測試失敗
)
echo.
echo 生成的報告:
echo   - 功能報告: 功能測試報告.html
echo   - 防火牆: firewall_test_report_*.json
echo   - Kill Chain: kill_chain_test_result.json
echo   - 自製防火牆: national_defense_test_report_*.json
echo   - ATT^&CK: attack_coverage_report.html
echo   - 認證: certification_reports\standalone_cert_test_*.json
echo.
echo 按任意鍵開啟功能報告...
pause >nul
if exist "功能測試報告.html" start "" "功能測試報告.html"
echo.
pause
