FROM nginx:alpine

# 安裝 htpasswd 工具
RUN apk add --no-cache apache2-utils

# 複製配置檔案
COPY nginx.conf /etc/nginx/nginx.conf

# 建立 SSL 目錄
RUN mkdir -p /etc/nginx/ssl

# 建立基本認證檔案（預設用戶：admin/password）
RUN echo 'admin:$apr1$rGj8vK9x$8QjKjKjKjKjKjKjKjKjKjK' > /etc/nginx/.htpasswd

# 建立自簽憑證（僅用於開發/測試）
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/C=TW/ST=Taiwan/L=Taipei/O=WAF-System/CN=localhost"

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]

