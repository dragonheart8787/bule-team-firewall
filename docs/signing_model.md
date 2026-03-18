# 🔐 簽章模型說明

## TSA 與 HSM 實作說明

**版本**: v1.0  
**適用**: 測試環境與生產環境

---

## 📋 當前實作（測試環境）

### Internal TSA (Simulated)

**說明**: 測試環境使用模擬的時間戳記授權機構 (TSA)

**實作細節**:
```python
def _generate_rfc3161_timestamp(self, data_hash: str) -> Dict:
    """
    生成 RFC 3161 時間戳記 (模擬)
    
    測試環境: Internal TSA (Simulated)
    正式環境: 可切換到企業 TSA 或 RFC3161 公有 TSA
    """
    return {
        "version": "RFC 3161",
        "timestamp": datetime.now().isoformat(),
        "hash_algorithm": "SHA-256",
        "message_imprint": data_hash,
        "tsa": "Internal TSA (Simulated)",
        "serial_number": secrets.token_hex(16)
    }
```

**使用場景**: 
- ✅ 開發測試
- ✅ 內部驗證
- ✅ 概念驗證 (PoC)

**限制**:
- ⚠️ 不具法律效力
- ⚠️ 時間戳可由系統管理員修改
- ⚠️ 不適用於正式投審或法庭證據

---

### HSM-Simulated (HMAC-SHA256)

**說明**: 測試環境使用 HMAC-SHA256 模擬 HSM 簽章

**實作細節**:
```python
class EvidenceVerificationSystem:
    def __init__(self):
        # 模擬 HSM 密鑰 (256-bit)
        self.hsm_key = secrets.token_bytes(32)
    
    def _hsm_sign(self, data: str) -> str:
        """
        HSM 簽章 (模擬 HMAC-SHA256)
        
        測試環境: 軟體 HMAC-SHA256
        正式環境: 實體 HSM (如 Thales Luna, AWS CloudHSM)
        """
        signature = hmac.new(
            self.hsm_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
```

**使用場景**:
- ✅ 開發與測試
- ✅ CI/CD 自動化
- ✅ 非關鍵簽章

**限制**:
- ⚠️ 密鑰存儲於軟體中
- ⚠️ 不符合 FIPS 140-3 Level 2+ 要求
- ⚠️ 不適用於正式密碼學操作

---

## 🔄 切換到正式環境

### 選項 1: 企業 TSA

**推薦服務商**:
- DigiCert TSA
- GlobalSign TSA
- Sectigo TSA

**切換步驟**:

| 步驟 | 動作 | 程式碼修改 |
|------|------|-----------|
| 1 | 註冊企業 TSA 服務 | 取得 API endpoint 與憑證 |
| 2 | 安裝 TSA 用戶端程式庫 | `pip install rfc3161ng` |
| 3 | 修改簽章函數 | 替換 `_generate_rfc3161_timestamp()` |
| 4 | 配置 TSA URL | `config/tsa_config.json` |
| 5 | 測試與驗證 | 驗證時間戳有效性 |

**程式碼範例**:
```python
from rfc3161ng import RemoteTimestamper

def _generate_rfc3161_timestamp_production(self, data_hash: str):
    """正式環境: 使用企業 TSA"""
    tsa_url = "https://tsa.example.com/timestamp"
    timestamper = RemoteTimestamper(tsa_url, certificate="tsa_cert.pem")
    
    timestamp_token = timestamper.timestamp(data=data_hash.encode())
    
    return {
        "version": "RFC 3161",
        "timestamp_token": timestamp_token.hex(),
        "tsa": tsa_url,
        "verified": timestamper.check(timestamp_token, data=data_hash.encode())
    }
```

---

### 選項 2: 公有 RFC3161 TSA

**免費服務**:
- FreeTSA.org
- Zeitstempel (DFN)

**切換步驟**: 同選項 1，但使用公有 TSA URL

**注意事項**:
- ⚠️ 公有 TSA 可能有速率限制
- ⚠️ 需要網路連線
- ✅ 具法律效力

---

### 選項 3: 實體 HSM

**推薦硬體**:
- Thales Luna HSM
- AWS CloudHSM
- Azure Dedicated HSM
- nCipher nShield

**切換步驟**:

| 步驟 | 動作 | 所需時間 |
|------|------|---------|
| 1 | 採購 HSM 硬體或雲端服務 | 1-2 週 |
| 2 | 安裝 HSM 用戶端程式庫 | 1 天 |
| 3 | 金鑰生成與註冊 | 1 天 |
| 4 | 修改簽章函數 | 2-3 天 |
| 5 | FIPS 140-3 認證 | 3-6 個月 |

**程式碼範例 (Thales Luna)**:
```python
from PyKCS11 import *

def _hsm_sign_production(self, data: str) -> str:
    """正式環境: 使用實體 HSM"""
    pkcs11 = PyKCS11Lib()
    pkcs11.load("/usr/lib/libCryptoki2_64.so")  # Luna HSM 程式庫
    
    session = pkcs11.openSession(slot)
    session.login("HSM_PIN")
    
    # 使用 HSM 內的私鑰簽章
    signature = session.sign(
        key_handle,
        data.encode(),
        Mechanism(CKM_SHA256_HMAC)
    )
    
    session.logout()
    return signature.hex()
```

**FIPS 140-3 合規**:
```python
{
  "hsm_model": "Thales Luna SA-7",
  "fips_140_3_level": "Level 3",
  "certificate_number": "PLACEHOLDER (待取得)",
  "key_storage": "HSM Protected (Tamper-evident)",
  "key_generation": "FIPS 186-4 compliant RNG",
  "algorithms": "CAVP Cert #XXXX"
}
```

---

## 📊 HSM-Simulated vs 實體 HSM 對照表

| 項目 | HSM-Simulated | 實體 HSM | 雲端 HSM |
|------|--------------|---------|----------|
| **密鑰存儲** | 軟體變數 | 硬體保護 | 雲端硬體 |
| **防篡改** | ❌ | ✅ Level 3 | ✅ Level 2/3 |
| **FIPS 140-3** | ❌ | ✅ | ✅ |
| **成本** | $0 | $5K-50K | $1-5/hour |
| **部署時間** | 即時 | 1-2 週 | 1 天 |
| **適用場景** | 測試/開發 | 正式環境 | 正式環境 |
| **法律效力** | ❌ | ✅ | ✅ |
| **認證時間** | N/A | 3-6 個月 | 已認證 |

---

## 🔄 替換流程（測試 → 生產）

### 階段 1: 測試環境 (當前)

```python
# evidence_verification_system.py (當前)
class EvidenceVerificationSystem:
    def __init__(self):
        self.hsm_key = secrets.token_bytes(32)  # 模擬
        self.tsa = "Internal TSA (Simulated)"
```

### 階段 2: 企業 TSA (第一步)

```python
# evidence_verification_system.py (企業 TSA)
class EvidenceVerificationSystem:
    def __init__(self):
        self.hsm_key = secrets.token_bytes(32)  # 仍為模擬
        self.tsa = "https://tsa.digicert.com"  # 企業 TSA
        self.tsa_cert = load_certificate("tsa_cert.pem")
```

**優勢**: 時間戳具法律效力，HSM 仍為模擬

### 階段 3: 雲端 HSM (快速部署)

```python
# evidence_verification_system.py (AWS CloudHSM)
import boto3

class EvidenceVerificationSystem:
    def __init__(self):
        self.hsm_client = boto3.client('cloudhsmv2')
        self.tsa = "https://tsa.digicert.com"
```

**優勢**: HSM 具 FIPS 140-3 認證，快速部署

### 階段 4: 實體 HSM (最高安全)

```python
# evidence_verification_system.py (Thales Luna)
from PyKCS11 import *

class EvidenceVerificationSystem:
    def __init__(self):
        self.hsm = PyKCS11Lib()
        self.hsm.load("/usr/lib/libCryptoki2_64.so")
        self.tsa = "https://tsa.digicert.com"
```

**優勢**: 最高安全等級，符合軍事級要求

---

## 🎯 切換決策矩陣

| 需求 | 推薦方案 | 時程 | 成本 |
|------|---------|------|------|
| **開發測試** | HSM-Simulated | 即時 | $0 |
| **內部投審** | 企業 TSA + HSM-Sim | 1 週 | $500/年 |
| **外部投審** | 企業 TSA + 雲端 HSM | 2 週 | $2K/年 |
| **正式部署** | 企業 TSA + 實體 HSM | 2-3 個月 | $20K+ |
| **軍事級** | 企業 TSA + FIPS L3 HSM | 6-12 個月 | $50K+ |

---

## 📝 配置範例

### config/crypto_backend.json

```json
{
  "environment": "production",
  
  "tsa": {
    "type": "enterprise",
    "url": "https://tsa.digicert.com",
    "certificate": "config/tsa_cert.pem",
    "retry": 3,
    "timeout": 30
  },
  
  "hsm": {
    "type": "cloud_hsm",
    "provider": "AWS CloudHSM",
    "cluster_id": "cluster-xxxxx",
    "key_id": "key-xxxxx",
    "fips_140_3_level": 2,
    "certificate_number": "4567"
  },
  
  "fallback": {
    "enabled": true,
    "method": "simulated",
    "note": "僅於 HSM 不可用時使用"
  }
}
```

---

## ✅ 驗證與審計

### 驗證 TSA 時間戳

```bash
# 使用 OpenSSL 驗證
openssl ts -verify \
  -in evidence/T1190_Test/timestamp.tsr \
  -data evidence/T1190_Test/test_data.json \
  -CAfile tsa_ca.pem

# 預期輸出: Verification: OK
```

### 驗證 HSM 簽章

```bash
# 驗證 HMAC-SHA256 簽章
python tools/verify_signing.py \
  --manifest evidence/master_manifest.json \
  --verify-all

# 預期輸出: 121/121 signatures verified
```

---

## 🎯 投審建議

### 測試/PoC 階段
```
✅ 使用: HSM-Simulated + Internal TSA
✅ 說明: "測試環境模擬，正式環境可替換"
✅ 成本: $0
```

### 正式投審階段
```
✅ 使用: 企業 TSA + 雲端 HSM
✅ 說明: "符合 FIPS 140-3 Level 2"
✅ 成本: $2K-5K/年
✅ 時程: 2-4 週
```

### 軍事級部署
```
✅ 使用: 企業 TSA + FIPS 140-3 Level 3 HSM
✅ 說明: "符合國防級密碼學要求"
✅ 成本: $50K+
✅ 時程: 6-12 個月
```

---

**結論**: 當前實作為測試環境模擬，具備完整的介面與流程。正式投審時，可透過配置檔切換到企業 TSA 與實體 HSM，無需修改核心邏輯。


