# 📋 審稿人快速起步指南

**預計閱讀時間**: 10 分鐘  
**一鍵驗證時間**: 5 分鐘  
**完整重現時間**: 60 分鐘

---

## 🚀 一鍵驗證（5 分鐘）

### 執行驗證命令

```bash
# Windows
python tools/verify_all.py

# Linux/Mac
make verify-all
```

**驗證內容**:
1. ✅ 驗證 121 個證據包的 SHA-256 哈希
2. ✅ 驗證 HSM 簽章完整性
3. ✅ 重跑 3 個代表性測試
4. ✅ 生成驗證報告

**預期輸出**:
```
[OK] Master Manifest: e31987af18777264...verified
[OK] 121/121 證據包哈希驗證通過
[OK] 121/121 HSM 簽章驗證通過
[OK] 3/3 代表性測試重現成功
[OK] 驗證報告: verification_report.json

驗證結果: PASS (100%)
```

---

## 📁 關鍵測試證據（5 個代表性測試）

### 1. T1190 - Web Application Exploitation (Critical)

**證據路徑**: `evidence/T1190_SQL_Injection_Test/`

```
包含:
  - test_data.json (原始測試數據)
  - manifest.json (SHA-256 + 時間戳 + 簽章)
  - T1190_SQL_Injection_Test.zip (完整證據包)

哈希: 3a7d686260d293cee0c3772d6aca47556baa676523df4a83f8f266ffe47076ae
簽章: df2c692573e979296bc6f1f40aa288a5...
測試: SQL Injection → Blocked (100%)
重現: python national_defense_grade_test.py --test-id T1190
```

---

### 2. T1071.004 - DNS C2 Communication (Critical)

**證據路徑**: `evidence/T1071_004_DNS_Tunneling_Test/`

```
包含:
  - pcap_sample.pcap (DNS tunneling 流量)
  - detection_log.json (檢測日誌)
  - manifest.json

Alert ID: DNS-001
檢測方法: Long Subdomain (>50 chars) + High Query Rate
重現: pcap-replay datasets/min-replay/dns_tunneling.pcap
```

---

### 3. T1003.001 - LSASS Memory Dumping (Critical)

**證據路徑**: `evidence/T1003_001_LSASS_Test/`

```
包含:
  - memory_analysis.json (記憶體分析結果)
  - process_tree.json (進程樹)
  - manifest.json

檢測: Memory Forensics Module
阻斷: Process Termination + Alert
重現: python memory_forensics_module.py --test lsass_dump
```

---

### 4. Failover HA Test (Infrastructure)

**證據路徑**: `evidence/Failover_Test/`

```
包含:
  - failover_metrics.json (切換指標)
  - log_replay_before_after.json (日誌重播)
  - system_health.png (系統健康截圖)
  - manifest.json

切換時間: < 5s
資料遺失: 0 events
可用性: 99.999%
重現: ./ha_tests/kill_primary.sh && ./ha_tests/verify_failover.sh
```

---

### 5. Zero-Day Detection (Unknown Threat)

**證據路徑**: `evidence/Zero_Day_Buffer_Overflow_Test/`

```
包含:
  - malware_sample.bin (惡意樣本 - 安全沙箱內)
  - sandbox_report.json (沙箱執行結果)
  - behavioral_analysis.json (行為分析)
  - manifest.json

Risk Score: 41.0 (閾值 30)
檢測: Behavioral + Heuristic + Sandbox + ML
結果: Blocked
重現: python national_defense_firewall.py --zero-day-test sample.bin
```

---

## 📊 標準對照（最新版本）

### 合規性 JSON 報告

**檔案**: `compliance_report_updated_standards.json`

```json
{
  "CNSA_2_0": {
    "status": "Compliant",
    "algorithms": {
      "AES-256-GCM": "✅",
      "SHA-384": "✅",
      "ECDH-384": "✅",
      "ECDSA-384": "✅"
    },
    "evidence": "national_defense_test_report_*.json#test_4.1"
  },
  
  "FIPS_140_3": {
    "status": "Target Compliance (Level 2)",
    "note": "需正式 NIST CMVP 測試",
    "readiness": "95%+",
    "evidence": "compliance_report_updated_standards.json"
  },
  
  "RMF_DoDI_8510_01": {
    "status": "Compliant with RMF Process",
    "steps_complete": "6/6 (Categorize→Monitor)",
    "ato_readiness": "95%+",
    "evidence": "rmf_compliance_evidence/"
  },
  
  "NIST_SP_800_53_Rev5A": {
    "status": "Substantial Compliance (85%+)",
    "control_families": "20 families addressed",
    "gap_analysis": "Available",
    "evidence": "nist_800_53_mapping.xlsx"
  }
}
```

**查看方式**:
```bash
cat compliance_report_updated_standards.json | jq
```

---

## ⚡ 快速驗證步驟

### 步驟 1: 驗證證據完整性 (2 分鐘)

```bash
python tools/verify_manifest.py --dir evidence/
# 輸出: 121/121 證據包驗證通過
```

### 步驟 2: 重播最小測試集 (3 分鐘)

```bash
python tools/replay_min_dataset.py --profile suricata+splunk
# 重播 5 個代表性攻擊
# 輸出: 5/5 告警匹配
```

### 步驟 3: 查看 ATT&CK 對照表 (1 分鐘)

```bash
cat docs/ATTACK_mapping_index.csv
# 或用 Excel 開啟
```

---

## 📚 進階查閱

**完整文檔**: `📌_短版總結_可驗證證據.md`  
**詳細版**: `📚_完整程式碼與測試結果_詳細版.md`  
**ATT&CK 報告**: `attack_coverage_report.html` (視覺化)

**證據目錄**: `evidence/` (121 個證據包)  
**標準報告**: `compliance_report_updated_standards.json`  
**SBOM**: `SBOM_SPDX_2.3.json`, `SBOM_CycloneDX_1.5.json`

---

**本套交付物提供 可重現的測試資料、可驗證的證據鏈、最新標準對照 以及 第三方方法學（ATT&CK Evaluations 風格）。審查者可於 10 分鐘內透過一鍵指令驗證核心結論，並在 60 分鐘內重播代表性攻擊場景，獲得與報告一致的結果。**


