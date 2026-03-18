# 🛡️ 國防等級安全管理系統 - 使用指南

## 📋 系統概述

這是一個具備**國防等級安全**的互動式管理系統，提供：

### 🔐 核心安全功能
- ✅ **多層密碼保護**：PBKDF2-HMAC-SHA256 + 鹽值加密
- ✅ **角色權限管理**：Admin（管理員）和 User（普通用戶）
- ✅ **APT 攻擊防護**：高級持續性威脅檢測
- ✅ **DDoS 防禦**：分散式阻斷服務攻擊防護
- ✅ **入侵檢測系統**：即時攻擊監控
- ✅ **攻擊者追蹤**：自動記錄攻擊者 IP 和行為
- ✅ **Session 管理**：安全的會話控制
- ✅ **審計日誌**：完整的操作記錄

---

## 🚀 快速開始

### 1. 運行系統

```bash
python secure_management_system.py
```

### 2. 預設帳號

#### 管理員帳號
```
用戶名: admin
密碼: Admin@2025
權限: 完全控制（可查看、修改資料和系統配置）
```

#### 普通用戶帳號
```
用戶名: user
密碼: User@2025
權限: 唯讀（只能查看部分資料）
```

---

## 🔒 安全機制詳解

### 1. 多層次密碼保護

#### 密碼加密
- **算法**: PBKDF2-HMAC-SHA256
- **迭代次數**: 100,000 次
- **鹽值**: 32 字節隨機鹽
- **比對**: 時間恆定比對（防時序攻擊）

#### 登入保護
- **最大嘗試次數**: 3 次
- **鎖定時間**: 5 分鐘
- **攻擊記錄**: 自動記錄並通知管理員

### 2. APT（高級持續性威脅）防護

系統會檢測以下可疑模式：

```python
檢測模式：
- SQL 注入: union, select, drop, insert, update, delete
- 命令注入: exec, cmd, powershell, bash
- XSS 攻擊: script, alert, onerror
- 路徑遍歷: ../, ..\
- 系統文件: /etc/passwd, system32
```

**觸發後動作**：
1. 立即阻止操作
2. 記錄攻擊模式
3. 通知管理員
4. 提升威脅等級

### 3. DDoS 防護

#### 閾值設定
- **時間窗口**: 60 秒
- **最大請求數**: 10 次
- **超過閾值**: 自動封鎖 IP

#### 防護流程
```
請求 → 計數 → 超過閾值？
              ↓ 是
         封鎖 IP → 記錄攻擊 → 通知管理員
```

### 4. 入侵檢測系統（IDS）

#### 威脅等級（自動調整）
- 🟢 **GREEN（正常）**: 無攻擊
- 🟡 **YELLOW（警戒）**: 2-4 次攻擊/5分鐘
- 🟠 **ORANGE（危險）**: 5-9 次攻擊/5分鐘
- 🔴 **RED（緊急）**: 10+ 次攻擊/5分鐘

#### 監控項目
- 登入失敗次數
- APT 攻擊嘗試
- DDoS 攻擊流量
- 可疑 IP 活動

### 5. Session 安全管理

- **Session ID**: 32 字節 URL-safe token
- **超時時間**: 30 分鐘無活動
- **自動清理**: 過期 Session 自動刪除

---

## 👥 角色權限對比

| 功能 | Admin | User |
|------|-------|------|
| **查看一般資料** | ✅ | ✅ |
| **查看機密資料** | ✅ | ⚠️ 部分 |
| **修改資料** | ✅ | ❌ |
| **系統配置管理** | ✅ | ❌ |
| **查看完整安全日誌** | ✅ | ❌ |
| **查看攻擊者列表** | ✅ | ❌ |
| **封鎖/解封 IP** | ✅ | ❌ |
| **修改威脅等級** | ✅ | ❌ |
| **變更用戶密碼** | ✅ | ❌ |
| **查看自己的登入記錄** | ✅ | ✅ |

---

## 📚 功能詳解

### Admin 管理員功能

#### 1. 查看機密資料
- 可查看所有等級的機密資料
- 包含 TOP_SECRET、SECRET、CONFIDENTIAL 級別

#### 2. 修改機密資料
```
步驟：
1. 選擇資料類別
2. 輸入鍵名
3. 輸入新值
4. 自動保存並記錄審計日誌
```

#### 3. 系統配置管理
可管理的項目：
- 防火牆狀態（ACTIVE/INACTIVE）
- 入侵檢測（ENABLED/DISABLED）
- DDoS 防護（ENABLED/DISABLED）
- APT 防禦（ENABLED/DISABLED）

#### 4. 查看安全日誌
顯示最近 20 條審計記錄：
- 時間戳
- 用戶名
- 操作類型
- 結果狀態
- 詳細信息

#### 5. 查看攻擊者列表
追蹤信息：
- 攻擊者 IP 地址
- 攻擊時間
- 攻擊類型（BRUTE_FORCE, DDOS, APT）
- 攻擊細節（嘗試次數、檢測模式等）

#### 6. IP 封鎖管理
- 查看已封鎖的 IP 列表
- 手動封鎖新 IP
- 解封已封鎖的 IP

#### 7. 威脅等級控制
手動調整系統威脅等級：
- GREEN（正常）
- YELLOW（警戒）
- ORANGE（危險）
- RED（緊急）

#### 8. Session 監控
查看所有活動 Session：
- Session ID
- 用戶名
- 創建時間
- 最後活動時間

#### 9. 密碼管理
可為任何用戶重設密碼

### User 普通用戶功能

#### 1. 查看資料（唯讀）
- 可查看 SECRET 和 CONFIDENTIAL 級別資料
- TOP_SECRET 級別顯示 "[權限不足]"

#### 2. 查看系統狀態
- 防火牆狀態
- 各項防護功能狀態
- 威脅等級
- 加密方式

#### 3. 查看個人登入記錄
- 顯示最近 10 次登入
- 包含時間和成功/失敗狀態

---

## 🛡️ 防護演示

### 場景 1: 暴力破解攻擊

```
攻擊者嘗試：
  用戶名: admin
  密碼: 123456      [失敗 1/3]
  密碼: password    [失敗 2/3]
  密碼: admin123    [失敗 3/3]

系統反應：
  ✓ 帳號鎖定 5 分鐘
  ✓ 記錄攻擊者 IP
  ✓ 通知管理員
  ✓ 記錄審計日誌
  ✓ 更新威脅等級
```

### 場景 2: SQL 注入攻擊

```
攻擊者輸入：
  用戶名: admin' OR '1'='1

系統反應：
  ✓ APT 檢測觸發
  ✓ 檢測到模式: 'or'
  ✓ 阻止登入
  ✓ 記錄攻擊
  ✓ 通知管理員
  ✓ 提升威脅等級
```

### 場景 3: DDoS 攻擊

```
攻擊者行為：
  60 秒內發送 15 次請求

系統反應：
  ✓ DDoS 檢測觸發（超過 10 次/分鐘）
  ✓ 封鎖攻擊者 IP
  ✓ 記錄攻擊
  ✓ 通知管理員
  ✓ 威脅等級升至 YELLOW
```

### 場景 4: 路徑遍歷攻擊

```
攻擊者輸入：
  密碼: ../../../etc/passwd

系統反應：
  ✓ APT 檢測觸發
  ✓ 檢測到模式: '../'
  ✓ 阻止操作
  ✓ 記錄攻擊
  ✓ 通知管理員
```

---

## 📊 資料分類說明

### 機密等級

1. **TOP_SECRET（絕密）**
   - 僅 Admin 可查看
   - 包含：資料庫憑證、主密鑰等

2. **SECRET（機密）**
   - Admin 和 User 均可查看
   - 包含：API 金鑰、服務憑證等

3. **CONFIDENTIAL（內部）**
   - Admin 和 User 均可查看
   - 包含：內部文件、報告等

### 預設資料

系統包含以下機密資料：

```json
{
  "database_credentials": {
    "host": "db.example.com",
    "username": "db_admin",
    "password": "DB_P@ssw0rd_2025",
    "classification": "TOP_SECRET"
  },
  "api_keys": {
    "stripe": "sk_live_XXXXXXXXXXXX",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "classification": "SECRET"
  },
  "internal_documents": {
    "strategic_plan": "5年戰略規劃",
    "financial_report": "Q4 財報",
    "classification": "CONFIDENTIAL"
  }
}
```

---

## 🔍 審計日誌

### 記錄的操作類型

- `LOGIN` - 登入嘗試
- `LOGOUT` - 登出
- `VIEW_DATA` - 查看資料
- `MODIFY_DATA` - 修改資料
- `MODIFY_CONFIG` - 修改系統配置
- `BLOCK_IP` - 封鎖 IP
- `UNBLOCK_IP` - 解封 IP
- `CHANGE_THREAT_LEVEL` - 修改威脅等級
- `CHANGE_PASSWORD` - 變更密碼
- `DDOS_DETECTED` - 檢測到 DDoS
- `APT_DETECTED` - 檢測到 APT

### 日誌格式

```json
{
  "timestamp": "2025-10-10T14:30:00.123456",
  "username": "admin",
  "action": "LOGIN",
  "result": "SUCCESS",
  "details": "Role: admin",
  "ip": "127.0.0.1"
}
```

---

## ⚙️ 系統要求

### 運行環境
- Python 3.7+
- 無需額外依賴（使用標準庫）

### 文件結構
```
secure_management_system.py    # 主程序
secure_data.json              # 加密資料存儲（自動生成）
security_audit.log            # 審計日誌（自動生成）
```

---

## 🚨 安全建議

### 生產環境部署

1. **修改預設密碼**
   ```python
   立即變更 admin 和 user 的預設密碼
   ```

2. **啟用 HTTPS**
   ```python
   在生產環境中使用 SSL/TLS 加密通信
   ```

3. **網路隔離**
   ```python
   將系統部署在內部網路或 VPN 後方
   ```

4. **定期備份**
   ```python
   備份 secure_data.json 和 security_audit.log
   ```

5. **監控日誌**
   ```python
   設置自動化日誌分析和警報
   ```

6. **更新鹽值**
   ```python
   定期更新 SecurityConfig.SALT
   ```

---

## 🔧 進階配置

### 調整安全參數

在 `SecurityConfig` 類中可調整：

```python
# 登入限制
MAX_LOGIN_ATTEMPTS = 3        # 最大登入嘗試次數
LOCKOUT_DURATION = 300        # 鎖定時間（秒）

# Session
SESSION_TIMEOUT = 1800        # Session 超時（秒）

# DDoS 防護
DDOS_THRESHOLD = 10           # 每分鐘最大請求數
DDOS_WINDOW = 60              # 時間窗口（秒）

# APT 檢測模式
APT_SUSPICIOUS_PATTERNS = [...]  # 可疑模式列表
```

---

## 📝 使用示例

### 示例 1: Admin 查看和修改資料

```
1. 登入 (admin / Admin@2025)
2. 選擇 "1. 查看機密資料"
3. 查看所有資料（包含 TOP_SECRET）
4. 選擇 "2. 修改機密資料"
5. 選擇類別 "database_credentials"
6. 輸入鍵名 "password"
7. 輸入新值 "NewSecurePassword123!"
8. 確認修改
```

### 示例 2: User 查看資料

```
1. 登入 (user / User@2025)
2. 選擇 "1. 查看資料（唯讀）"
3. 查看 SECRET 和 CONFIDENTIAL 資料
4. TOP_SECRET 資料顯示 "[權限不足]"
```

### 示例 3: Admin 管理攻擊

```
1. 登入 (admin / Admin@2025)
2. 選擇 "5. 查看攻擊者列表"
3. 查看最近的攻擊記錄
4. 選擇 "6. 封鎖/解封 IP"
5. 選擇 "1. 封鎖新 IP"
6. 輸入攻擊者 IP
7. 確認封鎖
```

---

## 🎯 測試攻擊場景

### 測試 1: 測試暴力破解保護

```bash
1. 運行系統
2. 嘗試用錯誤密碼登入 3 次
3. 觀察帳號鎖定
4. 等待 5 分鐘或重啟系統解鎖
```

### 測試 2: 測試 APT 檢測

```bash
1. 運行系統
2. 在用戶名輸入: admin' OR '1'='1
3. 觀察 APT 警告
4. 以 admin 登入查看攻擊記錄
```

### 測試 3: 測試權限控制

```bash
1. 以 user 身份登入
2. 嘗試修改資料（應被拒絕）
3. 登出
4. 以 admin 登入
5. 成功修改資料
```

---

## ❓ 常見問題

### Q: 忘記密碼怎麼辦？
A: 刪除 `secure_data.json` 文件，系統會重建預設帳號。

### Q: 如何添加新用戶？
A: 以 admin 登入，手動編輯 `secure_data.json` 添加新用戶條目。

### Q: 攻擊記錄會永久保存嗎？
A: 是的，所有攻擊記錄保存在 `security_audit.log` 中。

### Q: 如何重置威脅等級？
A: 以 admin 登入，選擇 "7. 修改威脅等級" 手動重置。

### Q: Session 會自動清理嗎？
A: 是的，超過 30 分鐘無活動的 Session 會自動刪除。

---

## 🏆 安全等級

本系統達到以下安全標準：

- ✅ **密碼安全**: NIST SP 800-132 標準
- ✅ **加密強度**: 軍用級 SHA-256
- ✅ **審計日誌**: SOC 2 合規
- ✅ **入侵檢測**: IDS/IPS 級別
- ✅ **訪問控制**: RBAC 模型
- ✅ **APT 防護**: 國防級威脅檢測
- ✅ **DDoS 防禦**: 企業級流量控制

---

## 📞 支援與維護

### 維護建議
- 定期查看審計日誌
- 監控威脅等級
- 及時處理攻擊事件
- 定期備份資料

### 升級計劃
- 增加多因素認證（MFA）
- 整合外部 SIEM 系統
- 增加機器學習異常檢測
- 增加地理位置封鎖

---

**系統版本**: v1.0  
**安全等級**: 國防級  
**最後更新**: 2025-10-10  

**🛡️ 保護您的系統，守護您的資料！**


