# 使用官方 Python 3.11 slim 作為基礎映像
FROM python:3.11-slim

# 設定工作目錄
WORKDIR /app

# 安裝系統依賴項，例如 curl 用於健康檢查
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 複製 WAF 代理伺服器的程式碼
COPY waf_proxy.py .

# 雖然目前的 waf_proxy.py 沒有外部 Python 依賴，但保留此步驟以方便未來擴展
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# 建立一個非 root 使用者來運行應用程式，增強安全性
RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser

# 複製程式碼到新使用者的家目錄
COPY --chown=appuser:appuser waf_proxy.py .

# 暴露 WAF 代理將監聽的埠號
EXPOSE 8080

# 設定環境變數的預設值
# 這些可以在 docker run 時被覆寫
ENV BACKEND_HOST="host.docker.internal"
ENV BACKEND_PORT="8000"
ENV PROXY_PORT="8080"

# 健康檢查指令，檢查 /healthz 端點
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

# 容器啟動時執行的命令
CMD ["python", "waf_proxy.py"]

