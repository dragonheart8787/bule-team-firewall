#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實軍事級加密系統
Real Military-Grade Cryptography System

功能特色：
- 真實的AES-256-GCM加密
- 真實的RSA-4096加密
- 真實的密鑰管理
- 真實的數位簽名
- 真實的密鑰派生
- 真實的隨機數生成
"""

import os
import hashlib
import hmac
import secrets
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import base64
import json
import threading
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.backends import default_backend
import sqlite3
import yaml

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """安全等級"""
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"

class KeyType(Enum):
    """密鑰類型"""
    AES_256 = "AES_256"
    RSA_4096 = "RSA_4096"
    ED25519 = "ED25519"
    X25519 = "X25519"

class KeyStatus(Enum):
    """密鑰狀態"""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    COMPROMISED = "COMPROMISED"
    EXPIRED = "EXPIRED"

@dataclass
class CryptographicKey:
    """密鑰物件"""
    id: str
    key_type: KeyType
    security_level: SecurityLevel
    key_data: bytes
    public_key: Optional[bytes]
    created_at: datetime
    expires_at: datetime
    status: KeyStatus
    usage_count: int
    max_usage: int
    owner: str
    metadata: Dict[str, Any]

@dataclass
class EncryptionResult:
    """加密結果"""
    ciphertext: bytes
    iv: bytes
    tag: bytes
    key_id: str
    algorithm: str
    timestamp: datetime

@dataclass
class DecryptionResult:
    """解密結果"""
    plaintext: bytes
    key_id: str
    algorithm: str
    timestamp: datetime
    verified: bool

class RealMilitaryCryptography:
    """真實軍事級加密系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.keys: Dict[str, CryptographicKey] = {}
        self.encryption_stats = {
            'encryptions': 0,
            'decryptions': 0,
            'key_rotations': 0,
            'failed_operations': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入現有密鑰
        self._load_keys()
        
        # 啟動密鑰輪換
        self._start_key_rotation()
        
        logger.info("真實軍事級加密系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('real_military_crypto.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cryptographic_keys (
                id TEXT PRIMARY KEY,
                key_type TEXT,
                security_level TEXT,
                key_data BLOB,
                public_key BLOB,
                created_at TIMESTAMP,
                expires_at TIMESTAMP,
                status TEXT,
                usage_count INTEGER,
                max_usage INTEGER,
                owner TEXT,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT,
                operation TEXT,
                algorithm TEXT,
                data_size INTEGER,
                timestamp TIMESTAMP,
                success BOOLEAN,
                error_message TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_keys(self):
        """載入密鑰"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM cryptographic_keys')
        rows = cursor.fetchall()
        
        for row in rows:
            key = CryptographicKey(
                id=row[0],
                key_type=KeyType(row[1]),
                security_level=SecurityLevel(row[2]),
                key_data=row[3],
                public_key=row[4],
                created_at=datetime.fromisoformat(row[5]),
                expires_at=datetime.fromisoformat(row[6]),
                status=KeyStatus(row[7]),
                usage_count=row[8],
                max_usage=row[9],
                owner=row[10],
                metadata=json.loads(row[11]) if row[11] else {}
            )
            self.keys[key.id] = key

    def generate_key(self, key_type: KeyType, security_level: SecurityLevel,
                    owner: str, expires_in_days: int = 365) -> CryptographicKey:
        """生成真實密鑰"""
        key_id = self._generate_key_id(key_type, security_level)
        
        if key_type == KeyType.AES_256:
            # 生成真實的AES-256密鑰
            key_data = secrets.token_bytes(32)  # 256 bits
            public_key = None
        elif key_type == KeyType.RSA_4096:
            # 生成真實的RSA-4096密鑰對
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            key_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif key_type == KeyType.ED25519:
            # 生成真實的Ed25519密鑰對
            private_key = ed25519.Ed25519PrivateKey.generate()
            key_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif key_type == KeyType.X25519:
            # 生成真實的X25519密鑰對
            private_key = x25519.X25519PrivateKey.generate()
            key_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError(f"不支援的密鑰類型: {key_type}")
        
        key = CryptographicKey(
            id=key_id,
            key_type=key_type,
            security_level=security_level,
            key_data=key_data,
            public_key=public_key,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=expires_in_days),
            status=KeyStatus.ACTIVE,
            usage_count=0,
            max_usage=1000000,
            owner=owner,
            metadata={}
        )
        
        self._save_key(key)
        self.keys[key_id] = key
        
        logger.info(f"已生成真實密鑰: {key_id} ({key_type.value})")
        return key

    def encrypt_data(self, data: bytes, key_id: str, 
                    additional_data: bytes = None) -> EncryptionResult:
        """真實加密數據"""
        if key_id not in self.keys:
            raise ValueError(f"密鑰不存在: {key_id}")
        
        key = self.keys[key_id]
        
        if key.status != KeyStatus.ACTIVE:
            raise ValueError(f"密鑰狀態無效: {key.status}")
        
        if key.usage_count >= key.max_usage:
            raise ValueError("密鑰使用次數已達上限")
        
        try:
            if key.key_type == KeyType.AES_256:
                result = self._encrypt_aes256(data, key, additional_data)
            elif key.key_type == KeyType.RSA_4096:
                result = self._encrypt_rsa4096(data, key)
            else:
                raise ValueError(f"不支援的加密類型: {key.key_type}")
            
            # 更新使用統計
            key.usage_count += 1
            self._save_key(key)
            self.encryption_stats['encryptions'] += 1
            
            # 記錄操作
            self._log_operation(key_id, "ENCRYPT", "SUCCESS", len(data))
            
            return result
        
        except Exception as e:
            self.encryption_stats['failed_operations'] += 1
            self._log_operation(key_id, "ENCRYPT", "FAILED", len(data), str(e))
            raise

    def _encrypt_aes256(self, data: bytes, key: CryptographicKey, 
                       additional_data: bytes = None) -> EncryptionResult:
        """真實AES-256-GCM加密"""
        # 生成真實的隨機IV
        iv = secrets.token_bytes(12)  # 96 bits for GCM
        
        # 建立真實的加密器
        cipher = Cipher(
            algorithms.AES(key.key_data),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # 添加額外認證數據
        if additional_data:
            encryptor.authenticate_additional_data(additional_data)
        
        # 真實加密數據
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return EncryptionResult(
            ciphertext=ciphertext,
            iv=iv,
            tag=encryptor.tag,
            key_id=key.id,
            algorithm="AES-256-GCM",
            timestamp=datetime.now()
        )

    def _encrypt_rsa4096(self, data: bytes, key: CryptographicKey) -> EncryptionResult:
        """真實RSA-4096加密"""
        # 載入真實的公鑰
        public_key = serialization.load_der_public_key(key.public_key, backend=default_backend())
        
        # RSA加密有大小限制，需要分塊處理
        max_chunk_size = 512  # RSA-4096 可以加密的最大數據塊大小
        chunks = [data[i:i+max_chunk_size] for i in range(0, len(data), max_chunk_size)]
        
        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        
        # 合併加密塊
        combined_ciphertext = b''.join(encrypted_chunks)
        
        return EncryptionResult(
            ciphertext=combined_ciphertext,
            iv=b'',  # RSA不需要IV
            tag=b'',  # RSA不需要tag
            key_id=key.id,
            algorithm="RSA-4096-OAEP",
            timestamp=datetime.now()
        )

    def decrypt_data(self, encrypted_data: EncryptionResult, 
                    additional_data: bytes = None) -> DecryptionResult:
        """真實解密數據"""
        if encrypted_data.key_id not in self.keys:
            raise ValueError(f"密鑰不存在: {encrypted_data.key_id}")
        
        key = self.keys[encrypted_data.key_id]
        
        if key.status != KeyStatus.ACTIVE:
            raise ValueError(f"密鑰狀態無效: {key.status}")
        
        try:
            if key.key_type == KeyType.AES_256:
                plaintext = self._decrypt_aes256(encrypted_data, key, additional_data)
            elif key.key_type == KeyType.RSA_4096:
                plaintext = self._decrypt_rsa4096(encrypted_data, key)
            else:
                raise ValueError(f"不支援的解密類型: {key.key_type}")
            
            # 更新統計
            self.encryption_stats['decryptions'] += 1
            
            # 記錄操作
            self._log_operation(encrypted_data.key_id, "DECRYPT", "SUCCESS", len(plaintext))
            
            return DecryptionResult(
                plaintext=plaintext,
                key_id=encrypted_data.key_id,
                algorithm=encrypted_data.algorithm,
                timestamp=datetime.now(),
                verified=True
            )
        
        except Exception as e:
            self.encryption_stats['failed_operations'] += 1
            self._log_operation(encrypted_data.key_id, "DECRYPT", "FAILED", 0, str(e))
            raise

    def _decrypt_aes256(self, encrypted_data: EncryptionResult, 
                       key: CryptographicKey, 
                       additional_data: bytes = None) -> bytes:
        """真實AES-256-GCM解密"""
        # 建立真實的解密器
        cipher = Cipher(
            algorithms.AES(key.key_data),
            modes.GCM(encrypted_data.iv, encrypted_data.tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # 添加額外認證數據
        if additional_data:
            decryptor.authenticate_additional_data(additional_data)
        
        # 真實解密數據
        plaintext = decryptor.update(encrypted_data.ciphertext) + decryptor.finalize()
        
        return plaintext

    def _decrypt_rsa4096(self, encrypted_data: EncryptionResult, 
                        key: CryptographicKey) -> bytes:
        """真實RSA-4096解密"""
        # 載入真實的私鑰
        private_key = serialization.load_der_private_key(
            key.key_data, password=None, backend=default_backend()
        )
        
        # 分塊解密
        chunk_size = 512  # RSA-4096 加密塊大小
        chunks = [encrypted_data.ciphertext[i:i+chunk_size] 
                 for i in range(0, len(encrypted_data.ciphertext), chunk_size)]
        
        decrypted_chunks = []
        for chunk in chunks:
            decrypted_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
        
        # 合併解密塊
        plaintext = b''.join(decrypted_chunks)
        
        return plaintext

    def sign_data(self, data: bytes, key_id: str) -> bytes:
        """真實數位簽名"""
        if key_id not in self.keys:
            raise ValueError(f"密鑰不存在: {key_id}")
        
        key = self.keys[key_id]
        
        if key.key_type == KeyType.ED25519:
            private_key = serialization.load_der_private_key(
                key.key_data, password=None, backend=default_backend()
            )
            signature = private_key.sign(data)
        elif key.key_type == KeyType.RSA_4096:
            private_key = serialization.load_der_private_key(
                key.key_data, password=None, backend=default_backend()
            )
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            raise ValueError(f"不支援的簽名類型: {key.key_type}")
        
        return signature

    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """真實驗證數位簽名"""
        if key_id not in self.keys:
            return False
        
        key = self.keys[key_id]
        
        try:
            if key.key_type == KeyType.ED25519:
                public_key = serialization.load_der_public_key(
                    key.public_key, backend=default_backend()
                )
                public_key.verify(signature, data)
            elif key.key_type == KeyType.RSA_4096:
                public_key = serialization.load_der_public_key(
                    key.public_key, backend=default_backend()
                )
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:
                return False
            
            return True
        
        except Exception:
            return False

    def derive_key(self, master_key: bytes, salt: bytes, 
                  info: bytes, length: int = 32) -> bytes:
        """真實密鑰派生"""
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return kdf.derive(master_key)

    def wrap_key(self, key_to_wrap: bytes, wrapping_key: bytes) -> bytes:
        """真實密鑰包裝"""
        return aes_key_wrap(wrapping_key, key_to_wrap, default_backend())

    def unwrap_key(self, wrapped_key: bytes, unwrapping_key: bytes) -> bytes:
        """真實密鑰解包"""
        return aes_key_unwrap(unwrapping_key, wrapped_key, default_backend())

    def rotate_key(self, key_id: str) -> CryptographicKey:
        """真實密鑰輪換"""
        if key_id not in self.keys:
            raise ValueError(f"密鑰不存在: {key_id}")
        
        old_key = self.keys[key_id]
        
        # 生成新密鑰
        new_key = self.generate_key(
            key_type=old_key.key_type,
            security_level=old_key.security_level,
            owner=old_key.owner
        )
        
        # 停用舊密鑰
        old_key.status = KeyStatus.INACTIVE
        self._save_key(old_key)
        
        # 啟用新密鑰
        new_key.status = KeyStatus.ACTIVE
        self._save_key(new_key)
        
        self.encryption_stats['key_rotations'] += 1
        
        logger.info(f"密鑰輪換完成: {key_id} -> {new_key.id}")
        return new_key

    def _start_key_rotation(self):
        """啟動真實密鑰輪換"""
        def rotation_loop():
            while True:
                try:
                    current_time = datetime.now()
                    
                    for key in self.keys.values():
                        # 檢查是否需要輪換
                        if (key.status == KeyStatus.ACTIVE and 
                            current_time >= key.expires_at - timedelta(days=7)):
                            self.rotate_key(key.id)
                    
                    time.sleep(86400)  # 每天檢查一次
                
                except Exception as e:
                    logger.error(f"密鑰輪換錯誤: {e}")
                    time.sleep(3600)  # 錯誤時等待1小時
        
        rotation_thread = threading.Thread(target=rotation_loop, daemon=True)
        rotation_thread.start()

    def _save_key(self, key: CryptographicKey):
        """儲存密鑰到資料庫"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO cryptographic_keys 
            (id, key_type, security_level, key_data, public_key, created_at, 
             expires_at, status, usage_count, max_usage, owner, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            key.id, key.key_type.value, key.security_level.value, key.key_data,
            key.public_key, key.created_at.isoformat(), key.expires_at.isoformat(),
            key.status.value, key.usage_count, key.max_usage, key.owner,
            json.dumps(key.metadata)
        ))
        self.db_conn.commit()

    def _log_operation(self, key_id: str, operation: str, result: str, 
                      data_size: int, error_message: str = None):
        """記錄操作日誌"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO encryption_logs 
            (key_id, operation, algorithm, data_size, timestamp, success, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            key_id, operation, "REAL_MILITARY_CRYPTO", data_size, 
            datetime.now().isoformat(), result == "SUCCESS", error_message
        ))
        self.db_conn.commit()

    def _generate_key_id(self, key_type: KeyType, security_level: SecurityLevel) -> str:
        """生成密鑰ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"REAL_{key_type.value}_{security_level.value}_{timestamp}"

    def get_key_statistics(self) -> Dict[str, Any]:
        """獲取密鑰統計"""
        return {
            'total_keys': len(self.keys),
            'active_keys': len([k for k in self.keys.values() if k.status == KeyStatus.ACTIVE]),
            'expired_keys': len([k for k in self.keys.values() if k.status == KeyStatus.EXPIRED]),
            'compromised_keys': len([k for k in self.keys.values() if k.status == KeyStatus.COMPROMISED]),
            'encryption_stats': self.encryption_stats,
            'keys_by_type': {
                key_type.value: len([k for k in self.keys.values() if k.key_type == key_type])
                for key_type in KeyType
            },
            'keys_by_security_level': {
                level.value: len([k for k in self.keys.values() if k.security_level == level])
                for level in SecurityLevel
            }
        }

    def export_key(self, key_id: str, format: str = "PEM") -> str:
        """匯出密鑰"""
        if key_id not in self.keys:
            raise ValueError(f"密鑰不存在: {key_id}")
        
        key = self.keys[key_id]
        
        if format == "PEM":
            if key.key_type == KeyType.RSA_4096:
                private_key = serialization.load_der_private_key(
                    key.key_data, password=None, backend=default_backend()
                )
                return private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
            else:
                return base64.b64encode(key.key_data).decode('utf-8')
        else:
            raise ValueError(f"不支援的格式: {format}")

    def revoke_key(self, key_id: str, reason: str = "Manual revocation"):
        """撤銷密鑰"""
        if key_id not in self.keys:
            raise ValueError(f"密鑰不存在: {key_id}")
        
        key = self.keys[key_id]
        key.status = KeyStatus.COMPROMISED
        key.metadata['revocation_reason'] = reason
        key.metadata['revocation_time'] = datetime.now().isoformat()
        
        self._save_key(key)
        logger.warning(f"密鑰已撤銷: {key_id}, 原因: {reason}")

def main():
    """主程式"""
    config = {
        'key_rotation_interval': 86400,  # 24小時
        'max_key_usage': 1000000,
        'default_key_lifetime': 365  # 天
    }
    
    crypto = RealMilitaryCryptography(config)
    
    # 生成真實測試密鑰
    aes_key = crypto.generate_key(
        KeyType.AES_256, 
        SecurityLevel.SECRET, 
        "test_user"
    )
    
    rsa_key = crypto.generate_key(
        KeyType.RSA_4096, 
        SecurityLevel.TOP_SECRET, 
        "test_user"
    )
    
    # 測試真實加密
    test_data = b"This is real military-grade test data"
    
    # AES加密
    encrypted = crypto.encrypt_data(test_data, aes_key.id)
    decrypted = crypto.decrypt_data(encrypted)
    
    print(f"AES真實加密測試: {decrypted.plaintext == test_data}")
    
    # RSA加密
    encrypted_rsa = crypto.encrypt_data(test_data, rsa_key.id)
    decrypted_rsa = crypto.decrypt_data(encrypted_rsa)
    
    print(f"RSA真實加密測試: {decrypted_rsa.plaintext == test_data}")
    
    # 測試真實簽名
    signature = crypto.sign_data(test_data, rsa_key.id)
    verified = crypto.verify_signature(test_data, signature, rsa_key.id)
    
    print(f"RSA真實簽名測試: {verified}")
    
    # 顯示統計
    stats = crypto.get_key_statistics()
    print(f"真實密鑰統計: {stats}")

if __name__ == "__main__":
    main()


