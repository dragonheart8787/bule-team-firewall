#!/bin/bash

# SSL 憑證管理腳本
# 支援 Let's Encrypt 自動更新和自簽憑證生成

set -e

CERT_DIR="/etc/nginx/ssl"
DOMAIN="${DOMAIN:-localhost}"
EMAIL="${EMAIL:-admin@example.com}"
CERT_TYPE="${CERT_TYPE:-self-signed}"  # self-signed 或 letsencrypt

# 建立憑證目錄
mkdir -p "$CERT_DIR"

if [ "$CERT_TYPE" = "letsencrypt" ]; then
    echo "使用 Let's Encrypt 生成憑證..."
    
    # 安裝 certbot
    if ! command -v certbot &> /dev/null; then
        echo "安裝 certbot..."
        apt-get update
        apt-get install -y certbot
    fi
    
    # 生成憑證
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN" \
        --cert-path "$CERT_DIR/cert.pem" \
        --key-path "$CERT_DIR/key.pem" \
        --fullchain-path "$CERT_DIR/fullchain.pem"
    
    # 設定自動更新
    echo "設定憑證自動更新..."
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook 'docker-compose -f /app/docker-compose.ha.yml restart nginx-lb'") | crontab -
    
else
    echo "生成自簽憑證..."
    
    # 生成私鑰
    openssl genrsa -out "$CERT_DIR/key.pem" 2048
    
    # 生成憑證簽名請求
    openssl req -new -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.csr" \
        -subj "/C=TW/ST=Taiwan/L=Taipei/O=WAF-System/CN=$DOMAIN"
    
    # 生成自簽憑證
    openssl x509 -req -days 365 -in "$CERT_DIR/cert.csr" \
        -signkey "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem"
    
    # 複製為 fullchain（自簽憑證不需要鏈）
    cp "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem"
    
    # 清理
    rm "$CERT_DIR/cert.csr"
fi

# 設定權限
chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"
chmod 644 "$CERT_DIR/fullchain.pem"

echo "SSL 憑證設定完成！"
echo "憑證位置: $CERT_DIR"
echo "域名: $DOMAIN"
echo "憑證類型: $CERT_TYPE"

