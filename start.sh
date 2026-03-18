#!/bin/bash
# 軍事級防火牆系統啟動腳本
# Military-Grade Firewall System Startup Script

echo "🛡️ 軍事級防火牆系統"
echo "=================================="

# 檢查Python版本
python_version=$(python3 --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python版本檢查通過: $python_version"
else
    echo "❌ 錯誤: 需要Python 3.8或更高版本"
    echo "當前版本: $python_version"
    exit 1
fi

# 檢查依賴套件
echo "📦 檢查依賴套件..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    echo "✅ 依賴套件檢查完成"
else
    echo "⚠️ 警告: requirements.txt 不存在"
fi

# 建立必要目錄
echo "📁 建立目錄結構..."
mkdir -p logs configs templates backups threat_intel
echo "✅ 目錄結構建立完成"

# 檢查配置檔案
if [ ! -f "firewall_config.yaml" ]; then
    echo "⚠️ 警告: 配置檔案不存在，將使用預設配置"
fi

# 檢查權限
if [ "$EUID" -ne 0 ]; then
    echo "⚠️ 警告: 建議以root權限運行以獲得完整功能"
    echo "使用: sudo $0"
fi

# 啟動系統
echo "🚀 啟動軍事級防火牆系統..."
echo "監控儀表板: http://localhost:5000"
echo "預設帳號: admin / military2024"
echo "按 Ctrl+C 停止系統"
echo "=================================="

python3 main.py "$@"

