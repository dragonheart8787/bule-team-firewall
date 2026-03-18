FROM ubuntu:20.04

# 安裝必要工具
RUN apt-get update && apt-get install -y \
    openssl \
    certbot \
    cron \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 複製憑證管理腳本
COPY cert-manager.sh /usr/local/bin/cert-manager.sh
RUN chmod +x /usr/local/bin/cert-manager.sh

# 建立憑證目錄
RUN mkdir -p /etc/nginx/ssl

# 設定環境變數
ENV DOMAIN=localhost
ENV EMAIL=admin@example.com
ENV CERT_TYPE=self-signed

# 預設執行憑證生成
CMD ["/usr/local/bin/cert-manager.sh"]

