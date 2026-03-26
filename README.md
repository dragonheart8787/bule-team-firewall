# 藍隊防禦系統（Blue Team Defense System）

企業級藍隊防禦平台，整合防火牆、IDS/IPS、威脅情報、SIEM、SOAR、零信任架構與數位取證等多層防禦能力。

---

## 功能特色

| 類別 | 功能 |
|------|------|
| 多層防禦 | DPI、IPS、APT 偵測、Zero-Day 防護、DLP |
| AD/DC 安全 | 攻擊路徑偵測、Kerberos 異常、特權群組監控 |
| 威脅獵殺 | MITRE ATT&CK 映射、Kill Chain 七階段偵測、CTI 整合 |
| 數位取證 | 記憶體取證（Volatility3）、PCAP 分析（dpkt）、證據鏈 |
| 自動化回應 | SOAR Playbook、蜜罐欺騙系統、紅隊模擬驗證 |
| 零信任架構 | 動態信任評分、持續驗證、最小權限存取 |
| 量子抗性加密 | 後量子密碼學整合、混合加密系統 |
| 高可用性 | SIEM 叢集、混沌工程驗證、負載測試 |

---

## 快速開始

```bash
# 安裝依賴
pip install -r requirements.txt

# 啟動完整防禦系統
python main.py --config config/firewall_config.yaml

# 防火牆能力驗證 [Real]
python tests/test_all_firewall_capabilities.py

# 國防等級整合測試 [Real + Simulation]
python tests/national_defense_grade_test.py

# 效能基準測試
python tests/run_benchmarks.py
```

---

## 專案結構

```
藍隊防禦系統/
├── main.py                    # 系統主入口
├── requirements.txt           # Python 依賴套件
├── Dockerfile                 # 容器映像
├── docker-compose.yml         # 標準容器部署
│
├── src/                       # 核心模組
│   ├── national_defense_firewall.py   # 主防火牆引擎（DPI、IPS、APT、DLP）
│   ├── intrusion_detection.py         # 入侵偵測系統（IDS/IPS）
│   ├── packet_filter.py               # 封包過濾規則引擎
│   ├── advanced_waf_system.py         # Web 應用防火牆（WAF）
│   ├── kill_chain_detector.py         # Kill Chain 七階段偵測
│   ├── mitre_attack_mapper.py         # MITRE ATT&CK 映射
│   ├── advanced_threat_hunting.py     # 進階威脅獵殺
│   ├── threat_intelligence.py         # 威脅情報管理
│   ├── cti_integration_engine.py      # 威脅情報整合引擎
│   ├── ml_anomaly_detector.py         # 機器學習異常偵測
│   ├── ad_attack_path_detector.py     # AD 攻擊路徑偵測
│   ├── kerberos_anomaly_detector.py   # Kerberos 異常偵測
│   ├── privileged_group_monitor.py    # 特權群組監控
│   ├── windows_event_parser.py        # Windows 事件日誌解析
│   ├── memory_forensics_module.py     # 記憶體取證（Volatility3）
│   ├── pcap_analysis_module.py        # PCAP 封包分析（dpkt）
│   ├── evidence_chain_system.py       # 數位證據鏈管理
│   ├── soar_playbooks.py              # SOAR 自動化劇本
│   ├── deception_honeypot.py          # 蜜罐欺騙系統
│   ├── red_team_simulation.py         # 紅隊攻擊模擬
│   ├── zero_trust_architecture.py     # 零信任架構引擎
│   ├── quantum_resistance.py          # 量子抗性加密
│   ├── dashboard.py                   # 防禦儀表板（Flask）
│   ├── audit_logger.py                # 稽核日誌系統
│   ├── config_manager.py              # 設定管理器
│   └── ...（其餘輔助模組）
│
├── engines/                   # 實際執行引擎
│   ├── ml_engine.py           # scikit-learn 機器學習引擎 [Real]
│   ├── pcap_engine.py         # dpkt 封包分析引擎 [Real]
│   ├── sandbox_engine.py      # Cuckoo 沙箱引擎 [Real，需部署]
│   └── volatility_engine.py   # Volatility3 記憶體分析 [Real，需安裝]
│
├── config/                    # 設定檔（YAML/XML）
│   ├── firewall_config.yaml
│   ├── suricata.yaml
│   ├── military_grade_firewall_config.yaml
│   ├── custom.rules           # Suricata 自訂規則
│   └── sysmonconfig.xml
│
├── tests/                     # 測試與驗證腳本
├── scripts/                   # 部署與工具腳本
├── docker/                    # 額外容器設定
│   ├── Dockerfile.siem
│   ├── Dockerfile.target_app
│   ├── docker-compose.ha.yml
│   ├── docker-compose.waf.yml
│   └── docker-compose.simple.yml
├── docs/                      # 技術文件
├── reports/                   # 測試報告輸出
├── data/                      # 資料庫與測試資料
├── evidence/                  # 數位取證證據
├── monitoring/                # Prometheus / Grafana 設定
├── playbooks/                 # SOAR Playbook（YAML）
├── performance/               # 效能基準測試模組
├── packet_capture/            # 封包擷取模組
├── go/                        # Go 語言高效能封包核心
├── k8s/                       # Kubernetes 部署設定
└── templates/                 # Web 介面模板
```

---

## 核心模組說明

### 防火牆與封包處理（`src/`）

| 模組 | 說明 |
|------|------|
| `national_defense_firewall.py` | 主防火牆引擎，整合 DPI、IPS、APT、DLP |
| `packet_filter.py` | 封包過濾規則引擎 |
| `intrusion_detection.py` | IDS/IPS，支援 ML 異常偵測與特徵比對 |
| `advanced_waf_system.py` | Web 應用防火牆，整合 ML 異常偵測 |
| `waf_proxy.py` | WAF 反向代理 |

### 威脅偵測（`src/`）

| 模組 | 說明 |
|------|------|
| `kill_chain_detector.py` | Cyber Kill Chain 七階段偵測 |
| `mitre_attack_mapper.py` | MITRE ATT&CK 框架映射 |
| `advanced_threat_hunting.py` | 進階威脅獵殺，整合圖分析與 ML |
| `ml_anomaly_detector.py` | Isolation Forest / DBSCAN 異常偵測 |
| `cti_integration_engine.py` | 威脅情報整合（IOC、TTP 管理） |

### AD/DC 安全（`src/`）

| 模組 | 說明 |
|------|------|
| `ad_attack_path_detector.py` | Active Directory 攻擊路徑偵測 |
| `kerberos_anomaly_detector.py` | Kerberos 協定異常與 Golden Ticket 偵測 |
| `privileged_group_monitor.py` | 特權群組異動即時監控 |
| `windows_event_parser.py` | Windows Security Event Log 解析 |

### 數位取證（`src/`）

| 模組 | 說明 |
|------|------|
| `memory_forensics_module.py` | 記憶體取證，整合 Volatility3 |
| `pcap_analysis_module.py` | PCAP 封包分析，整合 dpkt |
| `evidence_chain_system.py` | 數位證據鏈完整性管理 |

### 實際引擎（`engines/`）

| 引擎 | 模式 | 說明 |
|------|------|------|
| `ml_engine.py` | [Real] | scikit-learn 機器學習 |
| `pcap_engine.py` | [Real] | dpkt 封包分析 |
| `sandbox_engine.py` | [Real，需部署] | Cuckoo Sandbox 動態分析 |
| `volatility_engine.py` | [Real，需安裝] | Volatility3 記憶體分析 |

---

## 測試模式說明

| 模式 | 說明 |
|------|------|
| **[Real]** | 實際執行真實引擎，結果可重現 |
| **[Replay]** | 使用 PCAP / 樣本重播驗證 |
| **[Simulation]** | 模擬資料驗證邏輯正確性 |

| 指標 | 模式 | 備註 |
|------|------|------|
| 116.4 Gbps 處理能力 | [Simulation] | CPU 邏輯模擬，非實際線路吞吐量 |
| 1M 並發連線 | [Simulation] | 連線物件建立，非真實 TCP |
| DPI/IPS 回應 56–70 ms | [Real] | 實際計時量測 |
| ML / PCAP 引擎執行 | [Real] | scikit-learn、dpkt 實際執行 |

---

## Docker 部署

```bash
# 標準部署
docker-compose up -d

# 高可用性部署
docker-compose -f docker/docker-compose.ha.yml up -d

# WAF 模式部署
docker-compose -f docker/docker-compose.waf.yml up -d
```

---

## 外部依賴

| 套件／服務 | 用途 | 狀態 |
|-----------|------|------|
| `scikit-learn` | ML 異常偵測 | 已整合 |
| `dpkt` | PCAP 封包分析 | 已整合 |
| `flask` / `flask-socketio` | Web 儀表板 | 已整合 |
| `networkx` | 攻擊圖分析 | 已整合 |
| `volatility3` | 記憶體取證 | 需 `pip install volatility3` |
| Cuckoo Sandbox | 動態沙箱分析 | 需部署於 `localhost:8090` |
| Npcap（Windows） | 真實封包擷取 | 需另行安裝 |
| Suricata | IPS 規則引擎 | 需另行安裝 |

---

## 驗證測試

```bash
# 完整系統測試
python tests/run_complete_test.py

# 防火牆規則驗證
python tests/run_firewall_verify.py

# AD/DC 偵測驗證
python tests/test_ad_detection.py

# 合規框架測試
python tests/test_compliance_frameworks.py
```

---

## 系統監控

啟動後透過瀏覽器存取：

| 服務 | 網址 | 說明 |
|------|------|------|
| 防禦儀表板 | http://localhost:5000 | 主控台 |
| Grafana | http://localhost:3000 | 視覺化監控 |
| Prometheus | http://localhost:9090 | 指標收集 |

預設帳號：`admin` / `military2024`

---

## 相關文件

| 文件 | 說明 |
|------|------|
| [docs/TEST_MODE_CLARIFICATION.md](docs/TEST_MODE_CLARIFICATION.md) | 測試模式分層詳細說明 |
| [docs/ENTERPRISE_DEPLOYMENT_GUIDE.md](docs/ENTERPRISE_DEPLOYMENT_GUIDE.md) | 企業部署指南 |
| [docs/COMPLETE_SYSTEM_GUIDE.md](docs/COMPLETE_SYSTEM_GUIDE.md) | 系統完整使用手冊 |
| [docs/THESIS_REPORT_FINAL.md](docs/THESIS_REPORT_FINAL.md) | 技術研究報告 |

---

## 授權聲明

本專案僅供授權人員用於合法環境的資安防禦研究與測試，請勿用於未授權目標。
