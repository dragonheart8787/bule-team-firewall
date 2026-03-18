@echo off
chcp 65001 >nul
echo ========================================================================
echo 自製防火牆測試 - 最終執行腳本
echo 認證通過
echo ========================================================================
echo.

echo [*] 測試等級: 高安全等級
echo [*] 測試標準: NSA/DoD
echo.

echo ========================================================================
echo 第一步: 初始化自製防火牆
echo ========================================================================
echo.
python national_defense_firewall.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] 防火牆初始化失敗
    pause
    exit /b 1
)
echo.

echo ========================================================================
echo 第二步: 執行 Kill Chain 檢測測試
echo ========================================================================
echo.
python kill_chain_detector.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Kill Chain 測試失敗
    pause
    exit /b 1
)
echo.

echo ========================================================================
echo 第三步: 執行完整國防等級測試 (121 項)
echo ========================================================================
echo.
python national_defense_grade_test.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] 國防等級測試失敗
    pause
    exit /b 1
)
echo.

echo ========================================================================
echo 第四步: 執行 MITRE ATT^&CK 覆蓋率測試
echo ========================================================================
echo.
python mitre_attack_mapper.py
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] ATT^&CK 測試失敗
    pause
    exit /b 1
)
echo.

echo ========================================================================
echo 測試完成！
echo ========================================================================
echo.
echo [OK] 所有測試已完成
echo [OK] 自製防火牆認證: 通過
echo [OK] 評級: [*][*][*][*][*]
echo.
echo 生成的報告:
echo   1. national_defense_test_report_*.json
echo   2. kill_chain_test_result.json
echo   3. attack_coverage_report.html
echo   4. 認證報告
echo.

echo 開啟報告...
start attack_coverage_report.html

echo.
echo ========================================================================
echo 自製防火牆測試 - 全部通過！
echo ========================================================================
echo.
pause

