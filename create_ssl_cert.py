#!/usr/bin/env python3
"""
簡化的 SSL 憑證生成腳本
使用 Python 的 cryptography 庫生成自簽憑證
"""

import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def create_self_signed_cert():
    """建立自簽 SSL 憑證"""
    
    # 確保 ssl 目錄存在
    os.makedirs("ssl", exist_ok=True)
    
    # 生成私鑰
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # 建立憑證主體
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CRTO Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    # 建立憑證
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # 儲存私鑰
    with open("ssl/nginx.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # 儲存憑證
    with open("ssl/nginx.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("SSL 憑證生成成功！")
    print("憑證檔案: ssl/nginx.crt")
    print("私鑰檔案: ssl/nginx.key")

if __name__ == "__main__":
    try:
        create_self_signed_cert()
    except ImportError:
        print("需要安裝 cryptography 庫：")
        print("pip install cryptography")
    except Exception as e:
        print(f"生成憑證時發生錯誤: {e}")
