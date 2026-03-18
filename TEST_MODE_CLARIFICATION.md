# 測試模式分層說明

> **重要**：本專案所有測試與指標均明確標示為以下三種模式之一，避免過度包裝。

---

## 一、三層定義

| 模式 | 英文 | 定義 | 可信度 |
|------|------|------|--------|
| **Real Engine** | Real | 實際執行真實引擎，非模擬 | 高 |
| **Replay Mode** | Replay | 使用 PCAP/樣本檔案重播驗證 | 中 |
| **Simulation Mode** | Simulation | 模擬資料驗證邏輯正確性 | 低（僅驗證程式邏輯） |

---

## 二、各模組/指標對照表

### 2.1 引擎與分析

| 模組 | 模式 | 說明 | 外部依賴 |
|------|------|------|----------|
| **ML 異常檢測** | Real | scikit-learn Isolation Forest 實際執行 | `pip install scikit-learn` |
| **PCAP 分析** | Real | dpkt 實際解析 PCAP 檔案 | `pip install dpkt` |
| **沙箱分析** | Real / Simulation | Cuckoo API 可用時為 Real，否則 Fallback 啟發式 | Cuckoo 需運行於 localhost:8090 |
| **Volatility 記憶體取證** | Real / Simulation | volatility3 已安裝時為 Real | `pip install volatility3` |
| **封包擷取** | Real / Simulation | Npcap/Scapy 可用時為 Real 擷取 | Windows: Npcap, Linux: libpcap |

### 2.2 效能指標

| 指標 | 模式 | 測試方法 | 誠實說明 |
|------|------|----------|----------|
| **116.4 Gbps** | Simulation | 多進程模擬「封包處理迴圈」（decode 等輕量運算），非真實網路 I/O | **CPU 處理能力模擬**，非線路吞吐量。實機 10 Gbps 需硬體+網路環境 |
| **1M 並發** | Simulation | 在記憶體中建立 1M 個連線物件，驗證程式可處理此規模 | **連線物件建立速率**，非真實 TCP 連線 |
| **回應時間 56–70 ms** | Real | 實際呼叫 `national_defense_firewall` 方法計時 | 單次 DPI/IPS 呼叫延遲，已實測 |
| **10 Gbps / 1M 國防測試** | Simulation | 同上，僅驗證邏輯可處理設計目標 | 架構已完成，待實機驗證 |

### 2.3 防火牆能力測試

| 測試 | 模式 | 說明 |
|------|------|------|
| DPI (SQL/XSS/Command Injection) | Real | 真實字串傳入防火牆，實際 regex/邏輯檢測 |
| Signature IPS (Metasploit/Mimikatz) | Real | 真實特徵比對 |
| Zero-Day / 沙箱 / ML 分析 | Real / Simulation | 依引擎可用性，見 2.1 |
| 國防等級 121 項 | Real + Simulation | 邏輯檢測為 Real；部分需外部服務的為 Simulation |

### 2.4 需要外部元件的項目

| 項目 | 狀態 | 說明 |
|------|------|------|
| Cuckoo 沙箱 | 需部署 | `http://localhost:8090`，未運行則 Fallback |
| Volatility3 | 需安裝 | `pip install volatility3`，未安裝則 Fallback |
| Npcap (Windows) | 需安裝 | 真實封包擷取，未安裝則模擬模式 |
| 10 Gbps 線路 | 待實機 | 架構支援，需實體網路環境驗證 |
| AD/DC 環境 | 待實機 | AD 偵測模組已完成，需真實 AD 日誌驗證 |

---

## 三、報告撰寫原則

1. **不寫模糊句**：直接標 `[Real]`、`[Replay]`、`[Simulation]`
2. **效能數字必註**：如 `116.4 Gbps [Simulation]`、`1M 並發 [Simulation]`
3. **外部依賴必列**：哪些需 Cuckoo、Volatility、Npcap、AD 環境
4. **待驗證必註**：架構已完成但尚未實機驗證的項目

---

## 四、驗證測試

執行以下指令可驗證各模組實際模式：

```bash
# AD 偵測模組驗證
python tests/test_ad_detection.py

# 測試模式驗證 (Real/Simulation 標示)
python tests/test_mode_verification.py
```

---

## 五、快速查表

| 若你看到... | 代表 |
|-------------|------|
| `[Real]` | 實際執行，可重現 |
| `[Replay]` | 用 PCAP/樣本重播，可重現 |
| `[Simulation]` | 模擬資料，驗證邏輯 |
| `[需 Cuckoo]` | 需部署 Cuckoo Sandbox |
| `[需 Volatility3]` | 需 `pip install volatility3` |
| `[需 Npcap]` | 需安裝 Npcap (Windows) |
| `[架構完成，待實機]` | 程式碼就緒，尚未在真實環境驗證 |
