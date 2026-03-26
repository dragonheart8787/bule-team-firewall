#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級防火牆系統安裝腳本
Military-Grade Firewall System Installation Script
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def check_python_version():
    """檢查Python版本"""
    if sys.version_info < (3, 8):
        print("❌ 錯誤: 需要Python 3.8或更高版本")
        print(f"當前版本: {sys.version}")
        return False
    print(f"✅ Python版本檢查通過: {sys.version}")
    return True

def install_dependencies():
    """安裝依賴套件"""
    print("📦 正在安裝依賴套件...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ 依賴套件安裝完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 依賴套件安裝失敗: {e}")
        return False

def create_directories():
    """建立必要目錄"""
    print("📁 正在建立目錄結構...")
    
    directories = [
        "logs",
        "configs",
        "templates",
        "backups",
        "threat_intel"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ 建立目錄: {directory}")
    
    return True

def create_config_files():
    """建立配置檔案"""
    print("⚙️ 正在建立配置檔案...")
    
    # 檢查配置檔案是否存在
    if not Path("config/firewall_config.yaml").exists():
        print("⚠️ 配置檔案不存在，請手動建立或使用預設配置")
    
    return True

def check_permissions():
    """檢查權限"""
    print("🔐 檢查系統權限...")
    
    if platform.system() == "Linux":
        if os.geteuid() != 0:
            print("⚠️ 警告: 建議以root權限運行以獲得完整功能")
        else:
            print("✅ 具有管理員權限")
    
    return True

def create_systemd_service():
    """建立systemd服務檔案"""
    if platform.system() == "Linux":
        print("🔧 建立systemd服務檔案...")
        
        service_content = """[Unit]
Description=Military-Grade Firewall System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={}
ExecStart={} {}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""".format(os.getcwd(), sys.executable, os.path.join(os.getcwd(), "main.py"))
        
        service_file = "/etc/systemd/system/military-firewall.service"
        
        try:
            with open(service_file, "w") as f:
                f.write(service_content)
            print(f"✅ 服務檔案已建立: {service_file}")
            print("使用以下命令啟用服務:")
            print("sudo systemctl enable military-firewall")
            print("sudo systemctl start military-firewall")
        except PermissionError:
            print("⚠️ 需要root權限來建立系統服務檔案")
    
    return True

def main():
    """主安裝函數"""
    print("🛡️ 軍事級防火牆系統安裝程式")
    print("=" * 50)
    
    # 檢查Python版本
    if not check_python_version():
        sys.exit(1)
    
    # 安裝依賴
    if not install_dependencies():
        sys.exit(1)
    
    # 建立目錄
    if not create_directories():
        sys.exit(1)
    
    # 建立配置檔案
    if not create_config_files():
        sys.exit(1)
    
    # 檢查權限
    if not check_permissions():
        sys.exit(1)
    
    # 建立系統服務
    create_systemd_service()
    
    print("\n" + "=" * 50)
    print("🎉 安裝完成！")
    print("\n下一步:")
    print("1. 編輯配置檔案: config/firewall_config.yaml")
    print("2. 啟動系統: python main.py")
    print("3. 訪問儀表板: http://localhost:5000")
    print("4. 預設帳號: admin / military2024")
    print("\n如需幫助，請查看 README.md")

if __name__ == "__main__":
    main()

