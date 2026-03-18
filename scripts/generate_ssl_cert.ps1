# 生成 SSL 憑證的 PowerShell 腳本
Write-Host "生成 SSL 憑證..." -ForegroundColor Green

# 檢查 OpenSSL 是否可用
try {
    $opensslVersion = openssl version
    Write-Host "找到 OpenSSL: $opensslVersion" -ForegroundColor Green
} catch {
    Write-Host "未找到 OpenSSL，嘗試使用 Windows 內建工具..." -ForegroundColor Yellow
    
    # 使用 PowerShell 生成自簽憑證
    $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddDays(365)
    
    # 導出憑證
    $certPath = ".\ssl\nginx.crt"
    $keyPath = ".\ssl\nginx.key"
    
    # 確保目錄存在
    if (!(Test-Path ".\ssl")) {
        New-Item -ItemType Directory -Path ".\ssl" -Force
    }
    
    # 導出憑證檔案
    $cert | Export-Certificate -FilePath $certPath -Type CERT
    $cert | Export-PfxCertificate -FilePath ".\ssl\temp.pfx" -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)
    
    # 使用 certutil 導出私鑰
    certutil -exportPFX -p "password" ".\ssl\temp.pfx" ".\ssl\nginx.pem"
    
    Write-Host "憑證已生成到 ssl 目錄" -ForegroundColor Green
    Write-Host "憑證檔案: $certPath" -ForegroundColor Cyan
    Write-Host "私鑰檔案: $keyPath" -ForegroundColor Cyan
    
    # 清理臨時檔案
    Remove-Item ".\ssl\temp.pfx" -Force -ErrorAction SilentlyContinue
    Remove-Item ".\ssl\nginx.pem" -Force -ErrorAction SilentlyContinue
    
    exit 0
}

# 如果找到 OpenSSL，使用 OpenSSL 生成憑證
Write-Host "使用 OpenSSL 生成憑證..." -ForegroundColor Green

# 確保目錄存在
if (!(Test-Path ".\ssl")) {
    New-Item -ItemType Directory -Path ".\ssl" -Force
}

# 生成私鑰和憑證
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ".\ssl\nginx.key" -out ".\ssl\nginx.crt" -subj "/C=TW/ST=Taiwan/L=Taipei/O=CRTO Lab/OU=Security/CN=localhost"

if ($LASTEXITCODE -eq 0) {
    Write-Host "SSL 憑證生成成功！" -ForegroundColor Green
    Write-Host "憑證檔案: .\ssl\nginx.crt" -ForegroundColor Cyan
    Write-Host "私鑰檔案: .\ssl\nginx.key" -ForegroundColor Cyan
} else {
    Write-Host "SSL 憑證生成失敗！" -ForegroundColor Red
    exit 1
}

