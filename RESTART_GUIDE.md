# 🔄 服務重啟和深度測試指南

## ❌ 問題：服務被用戶中止

當前狀況：
- Target App: ❌ 已停止
- SIEM Dashboard: ❌ 已停止
- WAF Proxy: ❌ 已停止

---

## ✅ 解決方案：一鍵重啟和測試

### 方法 1: 使用批次檔（最簡單，推薦）

在文件管理器中：
1. 找到 `restart_and_test.bat`
2. **雙擊運行**

或在命令提示字元中：
```cmd
cd "C:\Users\User\Desktop\籃隊防禦系統"
restart_and_test.bat
```

**這個腳本會自動：**
- ✅ 停止所有現有 Python 進程
- ✅ 按順序啟動 Target App、SIEM、WAF（每個在獨立視窗）
- ✅ 等待服務就緒（15 秒）
- ✅ 檢查服務健康狀態
- ✅ 自動運行深度測試
- ✅ 顯示測試結果摘要

**預計總時間**: 約 6 分鐘

---

### 方法 2: 手動重啟（如果批次檔失敗）

#### 步驟 1: 停止所有 Python 進程

```cmd
taskkill /f /im python.exe
```

#### 步驟 2: 開啟 3 個新的命令提示字元視窗

**視窗 1 - Target App:**
```cmd
cd "C:\Users\User\Desktop\籃隊防禦系統"
python target_app_high_performance.py
```
看到 "Running on http://127.0.0.1:5000" 就表示成功

**視窗 2 - SIEM:**
```cmd
cd "C:\Users\User\Desktop\籃隊防禦系統"
python siem_dashboards.py
```
看到 "Uvicorn running on http://0.0.0.0:8001" 就表示成功

**視窗 3 - WAF:**
```cmd
cd "C:\Users\User\Desktop\籃隊防禦系統"
python waf_proxy_final_solution.py
```
看到 "WAF Proxy listening on port 8080" 就表示成功

#### 步驟 3: 等待 15 秒

讓所有服務完全啟動並初始化

#### 步驟 4: 檢查服務狀態

在新的命令提示字元中：
```cmd
cd "C:\Users\User\Desktop\籃隊防禦系統"
python check_services.py
```

應該看到：
```
[OK] Target App: 200
[OK] SIEM Health: 200
[OK] WAF Health: 200
[OK] WAF Status: 200
```

#### 步驟 5: 運行深度測試

```cmd
python advanced_test_methods.py
```

---

## 📊 深度測試內容

### 測試項目：

1. **高級連通性測試**
   - 測試所有服務端點
   - 驗證響應時間和狀態碼

2. **綜合 WAF 保護測試** ⭐
   - SQL 注入 (8 種攻擊向量)
   - XSS 攻擊 (8 種攻擊向量)
   - 路徑遍歷 (5 種攻擊向量)
   - 管理員路徑 (17 種路徑)
   - 命令注入 (7 種攻擊向量)
   - **總計 45+ 攻擊向量**

3. **壓力性能測試**
   - 輕量級: 5 並發 × 20 請求
   - 中等負載: 10 並發 × 15 請求
   - 高負載: 20 並發 × 10 請求

4. **SIEM 整合測試**
   - 測試所有 SIEM 端點
   - 驗證 WAF 到 SIEM 的事件傳遞

5. **系統資源測試**
   - CPU 使用率監控
   - 記憶體使用率監控
   - 磁碟使用率監控

6. **安全標頭測試**
   - 檢查 6 個關鍵安全標頭

---

## 🎯 預期測試結果

基於快速測試的 100% 通過率：

| 測試類別 | 預期結果 | 說明 |
|---------|---------|------|
| 連通性 | ✅ 100% | 所有服務正常 |
| WAF 保護 | ✅ 80-90% | SQL/XSS/路徑遍歷/命令注入全覆蓋 |
| 性能壓力 | ✅ 100% | 高並發下穩定運行 |
| SIEM 整合 | ✅ 85% | 可能有 1 個端點警告 |
| 系統資源 | ✅ PASS | 資源消耗在合理範圍 |
| 安全標頭 | ✅ 83% | 5/6 標頭（HSTS 需 HTTPS） |

**總體預期**: ✅ **85-90% 通過，達到企業級標準**

---

## 🔍 測試過程中的輸出

測試運行時，您會看到：

```
[啟動] 開始執行高級測試套件...
============================================================

[執行] 連通性測試...
[連通性] 執行高級連通性測試...
  [OK] Target App: 200 (0.XXXs)
  [OK] SIEM Health: 200 (0.XXXs)
  [OK] WAF Health: 200 (0.XXXs)

[執行] WAF 保護測試...
[WAF保護] 執行綜合 WAF 保護測試...
  測試 sql_injection...
    [BLOCKED] '; DROP TABLE users; --...
    [BLOCKED] 1' OR '1'='1...
    ...

[執行] 性能壓力測試...
[壓力測試] 執行壓力性能測試...
  執行 輕量級 測試...
    [統計] 成功率: 100.0%
    [統計] 平均響應時間: X.XXXs
    ...

[統計] 總測試時間: XXX.X 秒

[報告] 綜合測試報告摘要
============================================================
總測試類別: 4
通過類別: X
失敗類別: X
總體成功率: XX.X%
總體狀態: PASS/FAIL
```

---

## ⚠️ 故障排除

### 問題 1: 批次檔無法啟動服務

**解決**: 手動執行方法 2

### 問題 2: 端口被占用

```cmd
# 查看占用端口的進程
netstat -ano | findstr :5000
netstat -ano | findstr :8001
netstat -ano | findstr :8080

# 強制停止進程（將 PID 替換為實際值）
taskkill /PID <PID> /F
```

### 問題 3: 測試超時

**原因**: 服務未完全啟動
**解決**: 等待更長時間（30 秒），然後重新運行測試

### 問題 4: 權限錯誤

**解決**: 以管理員身分運行命令提示字元

---

## 📁 測試結果文件

測試完成後會生成：
- `ADVANCED_TEST_REPORT_YYYYMMDD_HHMMSS.json` - 詳細測試報告

查看結果摘要：
```cmd
python show_latest_results.py
```

---

## 🚀 快速開始

**最簡單的方式 - 只需一個命令：**

```cmd
restart_and_test.bat
```

然後等待約 6 分鐘，測試結果會自動顯示！

---

**創建時間**: 2025-10-10 01:50  
**狀態**: 就緒  
**難度**: ⭐ 簡單（一鍵完成）


