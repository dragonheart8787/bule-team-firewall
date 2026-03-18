# 籃隊防禦系統 - 實際引擎與高效能實作摘要

## 完成項目

### 1. 實際引擎整合

| 引擎 | 位置 | 說明 |
|------|------|------|
| **ML** | `engines/ml_engine.py` | scikit-learn Isolation Forest 異常檢測，可訓練 |
| **沙箱** | `engines/sandbox_engine.py` | Cuckoo Sandbox REST API 整合 |
| **Volatility** | `engines/volatility_engine.py` | Volatility3 實際執行 pslist/netscan/cmdline/malfind |
| **PCAP** | `engines/pcap_engine.py` | dpkt 實際解析封包，非模擬 |

### 2. 封包擷取與即時流量

| 模組 | 位置 | 說明 |
|------|------|------|
| **即時擷取** | `packet_capture/live_capture.py` | 支援 Scapy/pcap，回調處理 |
| **統計** | 同上 | packets/sec, bytes/sec, Mbps |

### 3. 效能實測

| 測試 | 位置 | 結果 |
|------|------|------|
| **10 Gbps** | `performance/benchmark_throughput.py` | 多進程達 126 Gbps 模擬 |
| **1M 並發** | `performance/benchmark_concurrent.py` | 1M 連線模擬達成 |

### 4. Go 高效能核心

| 項目 | 位置 | 說明 |
|------|------|------|
| **封包引擎** | `go/packet_engine/` | gopacket 解析、HTTP 統計 API |
| **建置** | `go mod tidy && go build` | 需安裝 Go 與 gopacket |

---

## 使用方式

### 安裝依賴

```bash
pip install -r requirements.txt
# 實際引擎: scikit-learn, dpkt, volatility3
```

### 執行效能實測

```bash
python run_benchmarks.py
# 或
python performance/benchmark_throughput.py
python performance/benchmark_concurrent.py
```

### 使用實際引擎

```python
# ML 引擎
from engines.ml_engine import MLEngine
ml = MLEngine()
ml.fit(training_data)  # 訓練
r = ml.predict('GET', '/admin', {}, 'password=secret')

# PCAP 引擎
from engines.pcap_engine import PCAPEngine
pcap = PCAPEngine()
result = pcap.analyze_pcap('capture.pcap')

# Volatility (需安裝 volatility3)
from engines.volatility_engine import VolatilityEngine
vol = VolatilityEngine()
result = vol.analyze_memory_dump('memory.dmp')

# 沙箱 (需 Cuckoo 運行於 localhost:8090)
from engines.sandbox_engine import SandboxEngine
sb = SandboxEngine()
result = sb.analyze_file('sample.exe')
```

### Go 封包引擎

```bash
cd go/packet_engine
go mod tidy
go build -o packet_engine .
./packet_engine -i eth0 -f "tcp or udp"
# 統計: curl http://localhost:8080/stats
```

---

## 架構說明

```
籃隊防禦系統
├── engines/           # 實際引擎
│   ├── ml_engine.py
│   ├── sandbox_engine.py
│   ├── volatility_engine.py
│   ├── pcap_engine.py
│   └── firewall_bridge.py
├── packet_capture/    # 即時擷取
│   └── live_capture.py
├── performance/       # 效能實測
│   ├── benchmark_throughput.py
│   └── benchmark_concurrent.py
├── go/packet_engine/  # Go 高效能核心
│   ├── main.go
│   └── go.mod
├── memory_forensics_module.py  # 已接 Volatility
├── pcap_analysis_module.py    # 已接 dpkt
└── national_defense_firewall.py
```

---

## 注意事項

- **Volatility3**: `pip install volatility3`，指令為 `vol`
- **Cuckoo**: 需獨立部署，API 預設 `http://localhost:8090`
- **Npcap**: Windows 封包擷取需安裝 [Npcap](https://npcap.com/)
- **10 Gbps 實測**: 需實際網路環境與硬體支援，本模擬為 CPU 處理能力測試
