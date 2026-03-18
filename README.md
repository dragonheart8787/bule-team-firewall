# 籃隊防禦系統

自製防火牆與資安防禦系統，涵蓋 DPI、IPS、APT、Zero-Day、DLP、AD/DC 偵測、記憶體取證、PCAP 分析、SOAR、CTI 等能力。

---

## ⚠️ 測試模式分層（必讀）

本專案**明確區分**三種測試模式，避免過度包裝：

| 模式 | 說明 |
|------|------|
| **[Real]** | 實際執行真實引擎，可重現 |
| **[Replay]** | 使用 PCAP/樣本重播驗證 |
| **[Simulation]** | 模擬資料驗證邏輯正確性 |

**詳細對照表**：請見 [TEST_MODE_CLARIFICATION.md](TEST_MODE_CLARIFICATION.md)

### 關鍵指標誠實標示

| 指標 | 模式 | 說明 |
|------|------|------|
| 116.4 Gbps | [Simulation] | CPU 處理能力模擬，非線路吞吐量 |
| 1M 並發 | [Simulation] | 連線物件建立，非真實 TCP |
| DPI/IPS 回應 56–70 ms | [Real] | 實際呼叫計時 |
| ML / PCAP 引擎 | [Real] | scikit-learn、dpkt 實際執行 |
| 沙箱 / Volatility | [Real] 或 [Simulation] | 依外部服務是否就緒 |

---

## 快速開始

```bash
# 防火牆能力測試 [Real]
python test_all_firewall_capabilities.py

# 國防等級測試 [Real + Simulation]
python national_defense_grade_test.py

# 效能實測（吞吐量 [Simulation]、並發 [Simulation]、引擎 [Real]）
python run_benchmarks.py

# AD/DC 偵測模組驗證（非僅 CLI，實際驗證邏輯）
python tests/test_ad_detection.py

# 測試模式驗證 (Real/Simulation 標示)
python tests/test_mode_verification.py
```

---

## 模組一覽

### 核心防禦
- `national_defense_firewall.py` - DPI、IPS、APT、Zero-Day、DLP
- `kill_chain_detector.py` - Kill Chain 7 階段
- `mitre_attack_mapper.py` - MITRE ATT&CK 映射

### AD/DC 偵測（新增）
- `windows_event_parser.py` - Windows 事件解析
- `ad_attack_path_detector.py` - AD 攻擊路徑偵測
- `kerberos_anomaly_detector.py` - Kerberos 異常偵測
- `privileged_group_monitor.py` - 特權群組監控

### 取證與分析
- `memory_forensics_module.py` - 記憶體取證 (Volatility)
- `pcap_analysis_module.py` - PCAP 分析 (dpkt)
- `evidence_chain_system.py` - 證據鏈

### 實際引擎 (engines/)
- `ml_engine.py` - scikit-learn [Real]
- `pcap_engine.py` - dpkt [Real]
- `sandbox_engine.py` - Cuckoo [Real 需部署]
- `volatility_engine.py` - Volatility3 [Real 需安裝]

---

## 外部依賴與待驗證

| 項目 | 狀態 |
|------|------|
| scikit-learn, dpkt | 已整合 [Real] |
| Cuckoo Sandbox | 需部署 localhost:8090 |
| Volatility3 | 需 `pip install volatility3` |
| Npcap (Windows) | 需安裝，真實封包擷取 |
| AD/DC 環境 | 架構完成，待實機驗證 |

---

## 報告

- [TEST_MODE_CLARIFICATION.md](TEST_MODE_CLARIFICATION.md) - 測試模式分層
- [系統能力與效能報告.md](系統能力與效能報告.md) - 能力與效能（含模式標示）
