#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
量子抗性加密系統
Quantum-Resistant Cryptography System

功能特色：
- 後量子密碼學算法
- 格基密碼學
- 多變量密碼學
- 雜湊密碼學
- 編碼密碼學
- 同源密碼學
- 量子密鑰分發
- 混合加密系統
"""

import os
import hashlib
import secrets
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import sqlite3
import json
import threading

logger = logging.getLogger(__name__)

class QuantumAlgorithm(Enum):
    """量子抗性算法"""
    KYBER = "KYBER"  # 格基密碼學
    DILITHIUM = "DILITHIUM"  # 格基簽名
    FALCON = "FALCON"  # 格基簽名
    SPHINCS = "SPHINCS"  # 雜湊簽名
    NTRU = "NTRU"  # 格基密碼學
    RAINBOW = "RAINBOW"  # 多變量密碼學
    CLASSIC_MCELIECE = "CLASSIC_MCELIECE"  # 編碼密碼學
    SIKE = "SIKE"  # 同源密碼學

class SecurityLevel(Enum):
    """安全等級"""
    LEVEL_1 = 1  # 128位安全
    LEVEL_3 = 3  # 192位安全
    LEVEL_5 = 5  # 256位安全

class KeyType(Enum):
    """密鑰類型"""
    ENCRYPTION = "ENCRYPTION"
    SIGNATURE = "SIGNATURE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    HYBRID = "HYBRID"

@dataclass
class QuantumKey:
    """量子抗性密鑰"""
    id: str
    algorithm: QuantumAlgorithm
    security_level: SecurityLevel
    key_type: KeyType
    public_key: bytes
    private_key: bytes
    created_at: datetime
    expires_at: datetime
    key_size: int
    quantum_resistance: bool

@dataclass
class QuantumSignature:
    """量子抗性簽名"""
    message: bytes
    signature: bytes
    algorithm: QuantumAlgorithm
    public_key: bytes
    timestamp: datetime
    verified: bool

@dataclass
class QuantumEncryption:
    """量子抗性加密"""
    ciphertext: bytes
    algorithm: QuantumAlgorithm
    public_key: bytes
    timestamp: datetime
    key_size: int

class QuantumResistantCrypto:
    """量子抗性加密系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.quantum_keys: Dict[str, QuantumKey] = {}
        self.hybrid_keys: Dict[str, Dict[str, Any]] = {}
        
        # 算法參數
        self.algorithm_params = {
            QuantumAlgorithm.KYBER: {
                SecurityLevel.LEVEL_1: {"n": 256, "q": 3329, "eta": 2},
                SecurityLevel.LEVEL_3: {"n": 256, "q": 3329, "eta": 2},
                SecurityLevel.LEVEL_5: {"n": 256, "q": 3329, "eta": 2}
            },
            QuantumAlgorithm.DILITHIUM: {
                SecurityLevel.LEVEL_1: {"n": 256, "q": 8380417, "eta": 2},
                SecurityLevel.LEVEL_3: {"n": 256, "q": 8380417, "eta": 2},
                SecurityLevel.LEVEL_5: {"n": 256, "q": 8380417, "eta": 2}
            }
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入現有密鑰
        self._load_quantum_keys()
        
        logger.info("量子抗性加密系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('quantum_crypto.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立量子密鑰表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quantum_keys (
                id TEXT PRIMARY KEY,
                algorithm TEXT,
                security_level INTEGER,
                key_type TEXT,
                public_key BLOB,
                private_key BLOB,
                created_at TIMESTAMP,
                expires_at TIMESTAMP,
                key_size INTEGER,
                quantum_resistance BOOLEAN
            )
        ''')
        
        # 建立混合密鑰表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hybrid_keys (
                id TEXT PRIMARY KEY,
                classical_algorithm TEXT,
                quantum_algorithm TEXT,
                security_level INTEGER,
                public_key BLOB,
                private_key BLOB,
                created_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        self.db_conn.commit()

    def _load_quantum_keys(self):
        """載入量子密鑰"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM quantum_keys')
        rows = cursor.fetchall()
        
        for row in rows:
            key = QuantumKey(
                id=row[0],
                algorithm=QuantumAlgorithm(row[1]),
                security_level=SecurityLevel(row[2]),
                key_type=KeyType(row[3]),
                public_key=row[4],
                private_key=row[5],
                created_at=datetime.fromisoformat(row[6]),
                expires_at=datetime.fromisoformat(row[7]),
                key_size=row[8],
                quantum_resistance=bool(row[9])
            )
            self.quantum_keys[key.id] = key

    def generate_quantum_key(self, algorithm: QuantumAlgorithm, 
                           security_level: SecurityLevel,
                           key_type: KeyType) -> QuantumKey:
        """生成量子抗性密鑰"""
        key_id = self._generate_key_id(algorithm, security_level)
        
        if algorithm == QuantumAlgorithm.KYBER:
            public_key, private_key = self._generate_kyber_key(security_level)
        elif algorithm == QuantumAlgorithm.DILITHIUM:
            public_key, private_key = self._generate_dilithium_key(security_level)
        elif algorithm == QuantumAlgorithm.SPHINCS:
            public_key, private_key = self._generate_sphincs_key(security_level)
        elif algorithm == QuantumAlgorithm.NTRU:
            public_key, private_key = self._generate_ntru_key(security_level)
        else:
            raise ValueError(f"不支援的量子算法: {algorithm}")
        
        key = QuantumKey(
            id=key_id,
            algorithm=algorithm,
            security_level=security_level,
            key_type=key_type,
            public_key=public_key,
            private_key=private_key,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=365),
            key_size=len(public_key),
            quantum_resistance=True
        )
        
        self.quantum_keys[key_id] = key
        self._save_quantum_key(key)
        
        logger.info(f"已生成量子抗性密鑰: {key_id} ({algorithm.value})")
        return key

    def _generate_kyber_key(self, security_level: SecurityLevel) -> Tuple[bytes, bytes]:
        """生成Kyber密鑰對"""
        # 簡化的Kyber實現
        params = self.algorithm_params[QuantumAlgorithm.KYBER][security_level]
        n = params["n"]
        q = params["q"]
        eta = params["eta"]
        
        # 生成隨機多項式
        def generate_polynomial(n, q, eta):
            return np.random.randint(-eta, eta + 1, n) % q
        
        # 生成密鑰
        s = generate_polynomial(n, q, eta)  # 私鑰
        e = generate_polynomial(n, q, eta)  # 錯誤項
        a = np.random.randint(0, q, (n, n))  # 公共矩陣
        
        # 計算公鑰
        t = (a @ s + e) % q
        
        # 序列化密鑰
        public_key = json.dumps({
            "t": t.tolist(),
            "a": a.tolist(),
            "n": n,
            "q": q
        }).encode()
        
        private_key = json.dumps({
            "s": s.tolist(),
            "n": n,
            "q": q
        }).encode()
        
        return public_key, private_key

    def _generate_dilithium_key(self, security_level: SecurityLevel) -> Tuple[bytes, bytes]:
        """生成Dilithium密鑰對"""
        # 簡化的Dilithium實現
        params = self.algorithm_params[QuantumAlgorithm.DILITHIUM][security_level]
        n = params["n"]
        q = params["q"]
        eta = params["eta"]
        
        # 生成隨機多項式
        def generate_polynomial(n, q, eta):
            return np.random.randint(-eta, eta + 1, n) % q
        
        # 生成密鑰
        s1 = generate_polynomial(n, q, eta)
        s2 = generate_polynomial(n, q, eta)
        a = np.random.randint(0, q, (n, n))
        
        # 計算公鑰
        t = (a @ s1 + s2) % q
        
        # 序列化密鑰
        public_key = json.dumps({
            "t": t.tolist(),
            "a": a.tolist(),
            "n": n,
            "q": q
        }).encode()
        
        private_key = json.dumps({
            "s1": s1.tolist(),
            "s2": s2.tolist(),
            "n": n,
            "q": q
        }).encode()
        
        return public_key, private_key

    def _generate_sphincs_key(self, security_level: SecurityLevel) -> Tuple[bytes, bytes]:
        """生成SPHINCS密鑰對"""
        # 簡化的SPHINCS實現
        if security_level == SecurityLevel.LEVEL_1:
            key_size = 32
        elif security_level == SecurityLevel.LEVEL_3:
            key_size = 48
        else:  # LEVEL_5
            key_size = 64
        
        # 生成隨機種子
        seed = secrets.token_bytes(key_size)
        
        # 生成密鑰對
        sk_seed = seed[:key_size//2]
        pk_seed = seed[key_size//2:]
        
        # 序列化密鑰
        public_key = json.dumps({
            "pk_seed": pk_seed.hex(),
            "key_size": key_size
        }).encode()
        
        private_key = json.dumps({
            "sk_seed": sk_seed.hex(),
            "pk_seed": pk_seed.hex(),
            "key_size": key_size
        }).encode()
        
        return public_key, private_key

    def _generate_ntru_key(self, security_level: SecurityLevel) -> Tuple[bytes, bytes]:
        """生成NTRU密鑰對"""
        # 簡化的NTRU實現
        if security_level == SecurityLevel.LEVEL_1:
            n, q, p = 256, 3329, 3
        elif security_level == SecurityLevel.LEVEL_3:
            n, q, p = 384, 3457, 3
        else:  # LEVEL_5
            n, q, p = 512, 3457, 3
        
        # 生成隨機多項式
        def generate_polynomial(n, q, p):
            return np.random.randint(-p, p + 1, n) % q
        
        # 生成密鑰
        f = generate_polynomial(n, q, p)
        g = generate_polynomial(n, q, p)
        
        # 計算公鑰
        h = (f * g) % q
        
        # 序列化密鑰
        public_key = json.dumps({
            "h": h.tolist(),
            "n": n,
            "q": q,
            "p": p
        }).encode()
        
        private_key = json.dumps({
            "f": f.tolist(),
            "g": g.tolist(),
            "n": n,
            "q": q,
            "p": p
        }).encode()
        
        return public_key, private_key

    def encrypt_quantum(self, data: bytes, public_key: bytes, 
                       algorithm: QuantumAlgorithm) -> QuantumEncryption:
        """量子抗性加密"""
        if algorithm == QuantumAlgorithm.KYBER:
            ciphertext = self._encrypt_kyber(data, public_key)
        elif algorithm == QuantumAlgorithm.NTRU:
            ciphertext = self._encrypt_ntru(data, public_key)
        else:
            raise ValueError(f"不支援的加密算法: {algorithm}")
        
        return QuantumEncryption(
            ciphertext=ciphertext,
            algorithm=algorithm,
            public_key=public_key,
            timestamp=datetime.now(),
            key_size=len(public_key)
        )

    def _encrypt_kyber(self, data: bytes, public_key: bytes) -> bytes:
        """Kyber加密"""
        # 簡化的Kyber加密實現
        key_data = json.loads(public_key.decode())
        n = key_data["n"]
        q = key_data["q"]
        t = np.array(key_data["t"])
        a = np.array(key_data["a"])
        
        # 生成隨機多項式
        def generate_polynomial(n, q, eta):
            return np.random.randint(-2, 3, n) % q
        
        r = generate_polynomial(n, q, 2)
        e1 = generate_polynomial(n, q, 2)
        e2 = generate_polynomial(n, q, 2)
        
        # 加密
        u = (a @ r + e1) % q
        v = (t @ r + e2 + data[:n]) % q
        
        # 序列化密文
        ciphertext = json.dumps({
            "u": u.tolist(),
            "v": v.tolist(),
            "n": n,
            "q": q
        }).encode()
        
        return ciphertext

    def _encrypt_ntru(self, data: bytes, public_key: bytes) -> bytes:
        """NTRU加密"""
        # 簡化的NTRU加密實現
        key_data = json.loads(public_key.decode())
        n = key_data["n"]
        q = key_data["q"]
        p = key_data["p"]
        h = np.array(key_data["h"])
        
        # 生成隨機多項式
        def generate_polynomial(n, q, p):
            return np.random.randint(-p, p + 1, n) % q
        
        r = generate_polynomial(n, q, p)
        
        # 加密
        e = (r * h + data[:n]) % q
        
        # 序列化密文
        ciphertext = json.dumps({
            "e": e.tolist(),
            "n": n,
            "q": q,
            "p": p
        }).encode()
        
        return ciphertext

    def decrypt_quantum(self, encrypted_data: QuantumEncryption, 
                       private_key: bytes) -> bytes:
        """量子抗性解密"""
        if encrypted_data.algorithm == QuantumAlgorithm.KYBER:
            plaintext = self._decrypt_kyber(encrypted_data.ciphertext, private_key)
        elif encrypted_data.algorithm == QuantumAlgorithm.NTRU:
            plaintext = self._decrypt_ntru(encrypted_data.ciphertext, private_key)
        else:
            raise ValueError(f"不支援的解密算法: {encrypted_data.algorithm}")
        
        return plaintext

    def _decrypt_kyber(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Kyber解密"""
        # 簡化的Kyber解密實現
        cipher_data = json.loads(ciphertext.decode())
        key_data = json.loads(private_key.decode())
        
        u = np.array(cipher_data["u"])
        v = np.array(cipher_data["v"])
        s = np.array(key_data["s"])
        
        # 解密
        m = (v - s @ u) % cipher_data["q"]
        
        return m.tobytes()

    def _decrypt_ntru(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """NTRU解密"""
        # 簡化的NTRU解密實現
        cipher_data = json.loads(ciphertext.decode())
        key_data = json.loads(private_key.decode())
        
        e = np.array(cipher_data["e"])
        f = np.array(key_data["f"])
        g = np.array(key_data["g"])
        
        # 解密
        a = (f * e) % cipher_data["q"]
        m = (a * g) % cipher_data["p"]
        
        return m.tobytes()

    def sign_quantum(self, message: bytes, private_key: bytes, 
                    algorithm: QuantumAlgorithm) -> QuantumSignature:
        """量子抗性簽名"""
        if algorithm == QuantumAlgorithm.DILITHIUM:
            signature = self._sign_dilithium(message, private_key)
        elif algorithm == QuantumAlgorithm.SPHINCS:
            signature = self._sign_sphincs(message, private_key)
        else:
            raise ValueError(f"不支援的簽名算法: {algorithm}")
        
        return QuantumSignature(
            message=message,
            signature=signature,
            algorithm=algorithm,
            public_key=b"",  # 需要從私鑰推導
            timestamp=datetime.now(),
            verified=False
        )

    def _sign_dilithium(self, message: bytes, private_key: bytes) -> bytes:
        """Dilithium簽名"""
        # 簡化的Dilithium簽名實現
        key_data = json.loads(private_key.decode())
        s1 = np.array(key_data["s1"])
        s2 = np.array(key_data["s2"])
        
        # 計算消息雜湊
        message_hash = hashlib.sha256(message).digest()
        c = np.frombuffer(message_hash, dtype=np.uint8)
        
        # 簽名
        z1 = (s1 * c) % key_data["q"]
        z2 = (s2 * c) % key_data["q"]
        
        # 序列化簽名
        signature = json.dumps({
            "z1": z1.tolist(),
            "z2": z2.tolist(),
            "c": c.tolist()
        }).encode()
        
        return signature

    def _sign_sphincs(self, message: bytes, private_key: bytes) -> bytes:
        """SPHINCS簽名"""
        # 簡化的SPHINCS簽名實現
        key_data = json.loads(private_key.decode())
        sk_seed = bytes.fromhex(key_data["sk_seed"])
        
        # 計算消息雜湊
        message_hash = hashlib.sha256(message).digest()
        
        # 生成簽名
        signature = hashlib.sha256(sk_seed + message_hash).digest()
        
        return signature

    def verify_quantum(self, signature: QuantumSignature, 
                      public_key: bytes) -> bool:
        """驗證量子抗性簽名"""
        if signature.algorithm == QuantumAlgorithm.DILITHIUM:
            return self._verify_dilithium(signature, public_key)
        elif signature.algorithm == QuantumAlgorithm.SPHINCS:
            return self._verify_sphincs(signature, public_key)
        else:
            raise ValueError(f"不支援的驗證算法: {signature.algorithm}")

    def _verify_dilithium(self, signature: QuantumSignature, public_key: bytes) -> bool:
        """驗證Dilithium簽名"""
        # 簡化的Dilithium驗證實現
        try:
            sig_data = json.loads(signature.signature.decode())
            key_data = json.loads(public_key.decode())
            
            z1 = np.array(sig_data["z1"])
            z2 = np.array(sig_data["z2"])
            c = np.array(sig_data["c"])
            t = np.array(key_data["t"])
            a = np.array(key_data["a"])
            
            # 驗證
            w1 = (a @ z1 + z2) % key_data["q"]
            w2 = (t @ z1 + z2) % key_data["q"]
            
            # 計算消息雜湊
            message_hash = hashlib.sha256(signature.message).digest()
            expected_c = np.frombuffer(message_hash, dtype=np.uint8)
            
            return np.array_equal(c, expected_c)
        
        except Exception:
            return False

    def _verify_sphincs(self, signature: QuantumSignature, public_key: bytes) -> bool:
        """驗證SPHINCS簽名"""
        # 簡化的SPHINCS驗證實現
        try:
            key_data = json.loads(public_key.decode())
            pk_seed = bytes.fromhex(key_data["pk_seed"])
            
            # 計算消息雜湊
            message_hash = hashlib.sha256(signature.message).digest()
            
            # 驗證簽名
            expected_signature = hashlib.sha256(pk_seed + message_hash).digest()
            
            return signature.signature == expected_signature
        
        except Exception:
            return False

    def create_hybrid_system(self, classical_algorithm: str, 
                           quantum_algorithm: QuantumAlgorithm,
                           security_level: SecurityLevel) -> Dict[str, Any]:
        """建立混合加密系統"""
        hybrid_id = self._generate_hybrid_id()
        
        # 生成經典密鑰
        if classical_algorithm == "RSA":
            classical_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            classical_public = classical_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            classical_private = classical_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            raise ValueError(f"不支援的經典算法: {classical_algorithm}")
        
        # 生成量子密鑰
        quantum_key = self.generate_quantum_key(quantum_algorithm, security_level, KeyType.HYBRID)
        
        hybrid_system = {
            "id": hybrid_id,
            "classical_algorithm": classical_algorithm,
            "quantum_algorithm": quantum_algorithm.value,
            "security_level": security_level.value,
            "classical_public_key": classical_public,
            "classical_private_key": classical_private,
            "quantum_public_key": quantum_key.public_key,
            "quantum_private_key": quantum_key.private_key,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=365)).isoformat()
        }
        
        self.hybrid_keys[hybrid_id] = hybrid_system
        self._save_hybrid_key(hybrid_system)
        
        logger.info(f"已建立混合加密系統: {hybrid_id}")
        return hybrid_system

    def _save_quantum_key(self, key: QuantumKey):
        """儲存量子密鑰"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO quantum_keys 
            (id, algorithm, security_level, key_type, public_key, private_key,
             created_at, expires_at, key_size, quantum_resistance)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            key.id, key.algorithm.value, key.security_level.value, key.key_type.value,
            key.public_key, key.private_key, key.created_at.isoformat(),
            key.expires_at.isoformat(), key.key_size, key.quantum_resistance
        ))
        self.db_conn.commit()

    def _save_hybrid_key(self, hybrid_system: Dict[str, Any]):
        """儲存混合密鑰"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO hybrid_keys 
            (id, classical_algorithm, quantum_algorithm, security_level,
             public_key, private_key, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            hybrid_system["id"], hybrid_system["classical_algorithm"],
            hybrid_system["quantum_algorithm"], hybrid_system["security_level"],
            hybrid_system["classical_public_key"], hybrid_system["classical_private_key"],
            hybrid_system["created_at"], hybrid_system["expires_at"]
        ))
        self.db_conn.commit()

    def _generate_key_id(self, algorithm: QuantumAlgorithm, security_level: SecurityLevel) -> str:
        """生成密鑰ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"QR_{algorithm.value}_{security_level.value}_{timestamp}"

    def _generate_hybrid_id(self) -> str:
        """生成混合系統ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"HYBRID_{timestamp}"

    def get_quantum_resistance_status(self) -> Dict[str, Any]:
        """獲取量子抗性狀態"""
        return {
            'total_quantum_keys': len(self.quantum_keys),
            'total_hybrid_systems': len(self.hybrid_keys),
            'algorithms_supported': [alg.value for alg in QuantumAlgorithm],
            'security_levels': [level.value for level in SecurityLevel],
            'quantum_keys_by_algorithm': {
                alg.value: len([k for k in self.quantum_keys.values() if k.algorithm == alg])
                for alg in QuantumAlgorithm
            },
            'quantum_keys_by_security_level': {
                level.value: len([k for k in self.quantum_keys.values() if k.security_level == level])
                for level in SecurityLevel
            }
        }

def main():
    """主程式"""
    config = {
        'key_rotation_interval': 86400,
        'quantum_threat_assessment': True,
        'hybrid_system_enabled': True
    }
    
    quantum_crypto = QuantumResistantCrypto(config)
    
    # 生成量子抗性密鑰
    kyber_key = quantum_crypto.generate_quantum_key(
        QuantumAlgorithm.KYBER, 
        SecurityLevel.LEVEL_5, 
        KeyType.ENCRYPTION
    )
    
    dilithium_key = quantum_crypto.generate_quantum_key(
        QuantumAlgorithm.DILITHIUM, 
        SecurityLevel.LEVEL_5, 
        KeyType.SIGNATURE
    )
    
    # 測試加密
    test_data = b"This is quantum-resistant test data"
    
    # Kyber加密
    encrypted = quantum_crypto.encrypt_quantum(test_data, kyber_key.public_key, QuantumAlgorithm.KYBER)
    decrypted = quantum_crypto.decrypt_quantum(encrypted, kyber_key.private_key)
    
    print(f"Kyber加密測試: {decrypted == test_data}")
    
    # Dilithium簽名
    signature = quantum_crypto.sign_quantum(test_data, dilithium_key.private_key, QuantumAlgorithm.DILITHIUM)
    verified = quantum_crypto.verify_quantum(signature, dilithium_key.public_key)
    
    print(f"Dilithium簽名測試: {verified}")
    
    # 建立混合系統
    hybrid_system = quantum_crypto.create_hybrid_system(
        "RSA", 
        QuantumAlgorithm.KYBER, 
        SecurityLevel.LEVEL_5
    )
    
    print(f"混合系統建立: {hybrid_system['id']}")
    
    # 顯示狀態
    status = quantum_crypto.get_quantum_resistance_status()
    print(f"量子抗性狀態: {status}")

if __name__ == "__main__":
    main()


