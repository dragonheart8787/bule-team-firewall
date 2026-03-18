@echo off
chcp 65001 > nul

SET SCRIPT_DIR=%~dp0
CD /D "%SCRIPT_DIR%"

ECHO ======================================================================
ECHO 進階防禦系統啟動
ECHO Advanced Defense System Startup
ECHO ======================================================================

ECHO.
ECHO [步驟 1/4] 重置密碼並確保系統就緒...
python reset_passwords.py
ECHO.

ECHO [步驟 2/4] 啟動核心 Web 系統...
start cmd /k "cd /d "%SCRIPT_DIR%" && python secure_web_system.py"
ECHO [OK] Web 系統已在獨立視窗啟動 (Port 5000)
ECHO.

ECHO [步驟 3/4] 啟動中央伺服器...
start cmd /k "cd /d "%SCRIPT_DIR%" && python central_server.py"
ECHO [OK] 中央伺服器已在獨立視窗啟動 (Port 9000)
ECHO.

ECHO [步驟 4/4] 等待服務就緒...
timeout /t 10 /nobreak > nul
ECHO [OK] 服務就緒
ECHO.

ECHO ======================================================================
ECHO 進階功能模組已就緒
ECHO ======================================================================
ECHO.
ECHO 可執行的進階功能:
ECHO.
ECHO   1. ATT^&CK 覆蓋率報告
ECHO      python mitre_attack_mapper.py
ECHO.
ECHO   2. 紅隊每日演練
ECHO      python red_team_ci_system.py
ECHO.
ECHO   3. SOAR Playbooks 示範
ECHO      python soar_playbooks.py
ECHO.
ECHO   4. 證據鏈系統示範
ECHO      python evidence_chain_system.py
ECHO.
ECHO   5. Memory Forensics 示範
ECHO      python memory_forensics_module.py
ECHO.
ECHO   6. PCAP 分析示範
ECHO      python pcap_analysis_module.py
ECHO.
ECHO   7. CTI 整合示範
ECHO      python cti_integration_engine.py
ECHO.
ECHO   8. 完整系統評估
ECHO      python advanced_defense_system.py
ECHO.
ECHO ======================================================================
ECHO 系統訪問地址:
ECHO ======================================================================
ECHO.
ECHO   Web 系統: http://127.0.0.1:5000
ECHO   中央伺服器: http://127.0.0.1:9000
ECHO.
ECHO   帳號:
ECHO     Admin: admin / Admin@2025
ECHO     User:  user  / User@2025
ECHO.
ECHO ======================================================================

PAUSE

