# 企業級 WAF 防護系統

## 🏢 企業級功能概覽

本系統已升級為企業級/雲端級防護解決方案，具備以下核心能力：

### 🔄 高可用性與負載平衡
- **多 WAF 實例**: 3個 WAF 實例提供 active-active 高可用
- **Nginx 負載平衡器**: 智能流量分配與健康檢查
- **自動故障轉移**: 實例故障時自動切換，RTO < 10秒
- **滾動更新**: 零停機部署與更新

### 🛡️ 進階安全防護
- **DDoS 防護**: 多層次速率限制與可疑行為檢測
- **TLS 終止**: 前端 SSL/TLS 處理，支援 HTTP/2
- **封鎖名單管理**: 持久化 IP 封鎖與 API 管理
- **行為分析**: 基於機器學習的可疑模式檢測

### 📊 監控與可觀察性
- **Prometheus 監控**: 完整的指標收集與告警
- **Grafana 儀表板**: 即時安全態勢感知
- **結構化日誌**: JSON 格式便於 SIEM 整合
- **健康檢查**: 多層次健康監控端點

### 🚀 自動化與 CI/CD
- **GitHub Actions**: 自動化測試、建置、部署
- **Kubernetes 支援**: 容器編排與自動擴縮
- **藍綠部署**: 零停機更新策略
- **回滾機制**: 快速恢復到穩定版本

## 🚀 快速開始

### 1. 基本部署（開發環境）
```bash
# 啟動基本服務
docker-compose up -d

# 檢查服務狀態
docker-compose ps
```

### 2. 企業級部署（高可用）
```bash
# 啟動高可用配置
docker-compose -f docker-compose.ha.yml up -d

# 檢查所有服務
docker-compose -f docker-compose.ha.yml ps
```

### 3. Kubernetes 部署
```bash
# 部署到 K8s
./scripts/deploy.sh staging

# 生產環境部署
./scripts/deploy.sh production
```

## 🔧 服務端點

### WAF 服務
- **HTTP**: http://localhost:80
- **HTTPS**: https://localhost:443
- **健康檢查**: http://localhost/healthz
- **指標**: http://localhost/metrics
- **管理 API**: http://localhost/api/blocklist

### SIEM 服務
- **API**: http://localhost:8001
- **健康檢查**: http://localhost:8001/healthz
- **指標**: http://localhost:8001/metrics
- **警報**: http://localhost:8001/alerts

### 監控服務
- **Grafana**: http://localhost:3000 (admin/admin123)
- **Prometheus**: http://localhost:9090

## 📈 效能指標

### 容量規劃
- **單實例處理能力**: 1,000 RPS
- **高可用配置**: 3,000+ RPS
- **延遲**: P95 < 30ms
- **可用性**: 99.9%+

### 資源需求
- **WAF 實例**: 512MB RAM, 0.5 CPU
- **SIEM 引擎**: 1GB RAM, 1 CPU
- **負載平衡器**: 256MB RAM, 0.25 CPU
- **監控系統**: 2GB RAM, 1 CPU

## 🔒 安全配置

### SSL/TLS 設定
```bash
# 使用 Let's Encrypt（生產環境）
export DOMAIN=your-domain.com
export EMAIL=admin@your-domain.com
export CERT_TYPE=letsencrypt
docker-compose -f docker-compose.ha.yml up ssl-manager

# 使用自簽憑證（測試環境）
export CERT_TYPE=self-signed
docker-compose -f docker-compose.ha.yml up ssl-manager
```

### 封鎖名單管理
```bash
# 查看封鎖清單
curl http://localhost/api/blocklist

# 封鎖 IP
curl -X POST http://localhost/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "action": "block"}'

# 解除封鎖
curl -X POST http://localhost/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "action": "unblock"}'
```

## 📊 監控與告警

### Grafana 儀表板
1. 開啟 http://localhost:3000
2. 使用 admin/admin123 登入
3. 查看 "WAF Security Dashboard"

### 關鍵指標
- **請求率**: 每秒處理的請求數
- **封鎖率**: 被 WAF 封鎖的請求比例
- **警報數**: SIEM 觸發的警報數量
- **實例健康**: 各 WAF 實例的運行狀態

### 告警規則
- 高請求率告警 (>100 req/s)
- WAF 實例故障告警
- DDoS 攻擊檢測告警
- SIEM 引擎故障告警

## 🔄 維護與更新

### 日常維護
```bash
# 查看日誌
docker-compose -f docker-compose.ha.yml logs -f

# 重啟服務
docker-compose -f docker-compose.ha.yml restart waf-proxy-1

# 更新配置
docker-compose -f docker-compose.ha.yml up -d --force-recreate
```

### 備份與恢復
```bash
# 備份封鎖名單
docker cp crto_waf_proxy_1:/data/blocklist.json ./backup/

# 恢復封鎖名單
docker cp ./backup/blocklist.json crto_waf_proxy_1:/data/
```

## 🚨 故障排除

### 常見問題
1. **服務無法啟動**: 檢查端口衝突和資源限制
2. **健康檢查失敗**: 確認服務正常運行和網路連通性
3. **高延遲**: 檢查資源使用率和網路狀況
4. **警報過多**: 調整檢測規則閾值

### 日誌分析
```bash
# WAF 日誌
docker-compose logs waf-proxy-1 | grep ERROR

# SIEM 日誌
docker-compose logs siem-engine | grep ALERT

# 負載平衡器日誌
docker-compose logs nginx-lb | grep error
```

## 📚 進階配置

### 自定義規則
編輯 `waf_proxy.py` 中的 `ModSecurityRules` 類別來添加自定義檢測規則。

### 監控自定義
修改 `monitoring/prometheus.yml` 和 `monitoring/grafana/` 目錄下的配置檔案。

### 擴展部署
使用 `k8s/waf-deployment.yaml` 在 Kubernetes 環境中部署和擴展。

## 🤝 支援與貢獻

- **問題回報**: 請在 GitHub Issues 中提交
- **功能請求**: 歡迎提交 Pull Request
- **文檔改進**: 協助完善文檔和範例

---

**注意**: 本系統僅供學習和研究使用，生產環境部署前請進行充分的安全評估和測試。

