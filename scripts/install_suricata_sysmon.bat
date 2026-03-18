@echo off
chcp 65001 >nul
title 安裝 Suricata 與 Sysmon

echo.
echo ================================================
echo   安裝 Suricata 與 Sysmon 用於威脅檢測
echo   Install Suricata & Sysmon for Threat Detection
echo ================================================
echo.

REM 檢查管理員權限
net session >nul 2>&1
if errorlevel 1 (
    echo ❌ 錯誤: 需要管理員權限運行此腳本
    echo 請右鍵點擊此批次檔並選擇 "以系統管理員身分執行"
    pause
    exit /b 1
)

echo ✅ 管理員權限確認

REM 檢查Chocolatey是否安裝
choco --version >nul 2>&1
if errorlevel 1 (
    echo 🔧 安裝 Chocolatey 包管理器...
    @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
    if errorlevel 1 (
        echo ❌ Chocolatey 安裝失敗
        pause
        exit /b 1
    )
    echo ✅ Chocolatey 安裝完成
)

REM 安裝必要套件
echo.
echo 🔧 安裝必要套件...

REM 安裝 Npcap (網路包捕獲驅動)
echo 📦 安裝 Npcap...
choco install npcap -y
if errorlevel 1 (
    echo ⚠️ Npcap 安裝可能需要手動完成，請訪問: https://npcap.com/
)

REM 安裝 Suricata
echo 📦 安裝 Suricata...
choco install suricata -y
if errorlevel 1 (
    echo ❌ Suricata 安裝失敗，嘗試手動下載...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.openinfosecfoundation.org/download/windows/suricata-7.0.2-1-64bit.exe' -OutFile 'suricata_installer.exe'"
    if exist "suricata_installer.exe" (
        echo 正在運行 Suricata 安裝程式...
        start /wait suricata_installer.exe
        del suricata_installer.exe
    )
)

REM 安裝 Sysmon
echo 📦 安裝 Sysmon...
choco install sysmon -y
if errorlevel 1 (
    echo 嘗試從 Microsoft 下載 Sysmon...
    powershell -Command "Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile 'Sysmon.zip'"
    if exist "Sysmon.zip" (
        powershell -Command "Expand-Archive -Path 'Sysmon.zip' -DestinationPath 'Sysmon' -Force"
        copy "Sysmon\Sysmon64.exe" "C:\Windows\System32\Sysmon.exe"
        del "Sysmon.zip"
        rd /s /q "Sysmon"
    )
)

REM 安裝 Python 套件
echo 📦 安裝 Python 套件...
pip install pywin32
if errorlevel 1 (
    echo ⚠️ pywin32 安裝失敗，Sysmon 監控可能無法正常工作
)

REM 配置 Suricata
echo.
echo 🔧 配置 Suricata...

REM 創建 Suricata 配置目錄
if not exist "C:\ProgramData\Suricata" mkdir "C:\ProgramData\Suricata"
if not exist "C:\ProgramData\Suricata\logs" mkdir "C:\ProgramData\Suricata\logs"
if not exist "C:\ProgramData\Suricata\rules" mkdir "C:\ProgramData\Suricata\rules"

REM 創建基本 Suricata 配置文件
(
echo # 基本 Suricata 配置
echo vars:
echo   address-groups:
echo     HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
echo     EXTERNAL_NET: "!$HOME_NET"
echo     HTTP_SERVERS: "$HOME_NET"
echo     SMTP_SERVERS: "$HOME_NET"
echo     SQL_SERVERS: "$HOME_NET"
echo     DNS_SERVERS: "$HOME_NET"
echo     TELNET_SERVERS: "$HOME_NET"
echo     AIM_SERVERS: "$EXTERNAL_NET"
echo     DC_SERVERS: "$HOME_NET"
echo     DNP3_SERVER: "$HOME_NET"
echo     DNP3_CLIENT: "$HOME_NET"
echo     MODBUS_CLIENT: "$HOME_NET"
echo     MODBUS_SERVER: "$HOME_NET"
echo     ENIP_CLIENT: "$HOME_NET"
echo     ENIP_SERVER: "$HOME_NET"
echo   port-groups:
echo     HTTP_PORTS: "80"
echo     SHELLCODE_PORTS: "!80"
echo     ORACLE_PORTS: 1521
echo     SSH_PORTS: 22
echo     DNP3_PORTS: 20000
echo     MODBUS_PORTS: 502
echo     FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
echo     FTP_PORTS: 21
echo     GENEVE_PORTS: 6081
echo     VXLAN_PORTS: 4789
echo     TEREDO_PORTS: 3544
echo.
echo outputs:
echo   - eve-log:
echo       enabled: yes
echo       filetype: regular
echo       filename: eve.json
echo       types:
echo         - alert
echo         - http
echo         - dns
echo         - tls
echo         - files
echo         - smtp
echo         - nfs
echo         - smb
echo         - krb5
echo         - ssh
echo         - stats
echo         - flow
echo.
echo af-packet:
echo   - interface: default
echo     cluster-id: 99
echo     cluster-type: cluster_flow
echo     defrag: yes
echo.
echo default-rule-path: C:\ProgramData\Suricata\rules
echo rule-files:
echo   - suricata.rules
echo.
echo classification-file: classification.config
echo reference-config-file: reference.config
echo.
echo logging:
echo   default-log-level: notice
echo   outputs:
echo   - console:
echo       enabled: yes
echo   - file:
echo       enabled: yes
echo       level: info
echo       filename: suricata.log
) > "C:\ProgramData\Suricata\suricata.yaml"

REM 創建基本規則文件
(
echo # 基本威脅檢測規則
echo alert tcp any any -^> $HOME_NET any ^(msg:"Possible malware communication"; flow:established; content:"malware"; sid:1000001;^)
echo alert dns any any -^> any any ^(msg:"Suspicious DNS query"; dns.query; content:"malicious"; sid:1000002;^)
echo alert http any any -^> any any ^(msg:"Suspicious HTTP request"; http.uri; content:"/malware"; sid:1000003;^)
echo alert tcp any any -^> any any ^(msg:"Port scan detected"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000004;^)
) > "C:\ProgramData\Suricata\rules\suricata.rules"

echo ✅ Suricata 配置完成

REM 配置 Sysmon
echo.
echo 🔧 配置 Sysmon...

REM 檢查配置文件是否存在
if not exist "sysmonconfig.xml" (
    echo ❌ 錯誤: 未找到 sysmonconfig.xml 配置文件
    echo 請確保 sysmonconfig.xml 文件在當前目錄中
    pause
    exit /b 1
)

REM 安裝 Sysmon 配置
echo 安裝 Sysmon 配置...
sysmon -accepteula -i sysmonconfig.xml
if errorlevel 1 (
    echo ⚠️ Sysmon 配置安裝可能失敗，請手動執行: sysmon -accepteula -i sysmonconfig.xml
) else (
    echo ✅ Sysmon 配置安裝完成
)

REM 啟動服務
echo.
echo 🚀 啟動服務...

REM 檢查 Sysmon 服務狀態
sc query Sysmon >nul 2>&1
if errorlevel 1 (
    echo ⚠️ Sysmon 服務未安裝或未啟動
) else (
    echo ✅ Sysmon 服務運行中
)

echo.
echo ================================================
echo   安裝完成！
echo ================================================
echo.
echo 📍 重要文件位置:
echo   - Suricata 配置: C:\ProgramData\Suricata\suricata.yaml
echo   - Suricata 日誌: C:\ProgramData\Suricata\logs\eve.json
echo   - Sysmon 配置: sysmonconfig.xml
echo   - Sysmon 日誌: Windows 事件檢視器 ^> Applications and Services Logs ^> Microsoft ^> Windows ^> Sysmon
echo.
echo 🔧 手動啟動指令:
echo   - 啟動 Suricata: suricata -c C:\ProgramData\Suricata\suricata.yaml -i ethernet_adapter_name
echo   - 重新安裝 Sysmon: sysmon -accepteula -i sysmonconfig.xml
echo.
echo 🚀 現在可以運行真實終極軍事防禦系統:
echo   start_real_ultimate_defense.bat
echo.
pause

