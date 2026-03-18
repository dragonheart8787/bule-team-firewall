# WAF 快速部署（Windows / Docker Desktop）

## 需求
- 安裝 Docker Desktop（Windows）

## 啟動
1. 在專案根目錄執行：
```
docker compose -f docker-compose.waf.yml up -d
```
2. 將前端/後端服務流量導到此 WAF：瀏覽 http://localhost:8080

## 檔案說明
- `waf/nginx.conf`：Nginx 前置代理，已留出 ModSecurity 啟用位點
- `waf/modsecurity.conf`：ModSecurity 設定，預設可載入 OWASP CRS
- `docker-compose.waf.yml`：啟動 WAF 容器，預設對外 8080

## 自訂 OWASP CRS
可將官方 CRS 規則掛載進容器（參考 compose 中掛載行註解），或沿用內建。

## 驗證
1. 造訪 http://localhost:8080 透過 WAF 代理到後端
2. 嘗試常見攻擊字串（如 `../etc/passwd`、簡單 XSS）應被攔截並回應 403






