# 高效能封包處理引擎 (Go)

## 目標
- **10 Gbps** 吞吐量
- **1M** 並發連線處理
- 取代 Python 關鍵路徑以達成高效能

## 建置

```bash
cd go/packet_engine
go mod tidy
go build -o packet_engine .
```

## 執行

```bash
# 指定網路介面
./packet_engine -i eth0 -f "tcp or udp"

# 查詢統計 (HTTP)
curl http://localhost:8080/stats
```

## 輸出範例

```json
{
  "packets_processed": 1234567,
  "bytes_processed": 1851850500,
  "duration_seconds": 10.5,
  "packets_per_second": 117577,
  "bytes_per_second": 176365714,
  "gbps": 1.41
}
```

## 與 Python 整合

可透過 gRPC 或 REST API 與 Python 防火牆整合：
- Go 引擎負責封包擷取、初步過濾、流量統計
- Python 負責 DPI、ML、沙箱等進階分析
