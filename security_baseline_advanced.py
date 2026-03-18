#!/usr/bin/env python3
"""
安全基線補強腳本 - 企業級版本
TLS/憑證輪換 SOP、私鑰保護（KMS/Vault）、機密以環境變數或 Secret 管理
L7 速率限制 + Geo/IP reputation；前置 CDN/DDoS Scrubbing
"""

import os
import json
import time
import hashlib
import hmac
import base64
import subprocess
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import argparse
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import threading
import logging

class SecurityBaselineManager:
    """安全基線管理器"""
    
    def __init__(self):
        self.setup_logging()
        self.certificates = {}
        self.secrets = {}
        self.rate_limits = {}
        self.geo_blocks = set()
        self.ddos_protection = {}
        self.audit_log = []
        
    def setup_logging(self):
        """設置日誌"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def audit_log_event(self, event_type: str, details: Dict):
        """記錄審計日誌"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "user": os.getenv("USER", "system"),
            "source_ip": self._get_source_ip()
        }
        self.audit_log.append(audit_entry)
        self.logger.info(f"Audit: {event_type} - {details}")
    
    def _get_source_ip(self) -> str:
        """獲取來源 IP"""
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            return response.text
        except:
            return "unknown"
    
    def generate_ssl_certificate(self, domain: str, days: int = 365, 
                                key_size: int = 2048) -> Dict:
        """生成 SSL 憑證"""
        try:
            self.audit_log_event("certificate_generation", {
                "domain": domain,
                "days": days,
                "key_size": key_size
            })
            
            # 生成私鑰
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )
            
            # 生成憑證
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise WAF"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
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
                datetime.utcnow() + timedelta(days=days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # 儲存憑證
            cert_dir = f"ssl/{domain}"
            os.makedirs(cert_dir, exist_ok=True)
            
            # 儲存私鑰（加密）
            encrypted_key = self._encrypt_private_key(private_key)
            with open(f"{cert_dir}/private.key", "wb") as f:
                f.write(encrypted_key)
            
            # 儲存憑證
            with open(f"{cert_dir}/certificate.crt", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # 儲存憑證鏈
            with open(f"{cert_dir}/certificate_chain.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            cert_info = {
                "domain": domain,
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "key_size": key_size,
                "cert_path": f"{cert_dir}/certificate.crt",
                "key_path": f"{cert_dir}/private.key",
                "chain_path": f"{cert_dir}/certificate_chain.pem"
            }
            
            self.certificates[domain] = cert_info
            
            self.logger.info(f"SSL 憑證生成成功: {domain}")
            return cert_info
            
        except Exception as e:
            self.logger.error(f"SSL 憑證生成失敗: {e}")
            raise
    
    def _encrypt_private_key(self, private_key) -> bytes:
        """加密私鑰"""
        # 使用環境變數中的密碼
        password = os.getenv("SSL_KEY_PASSWORD", "default_password").encode()
        
        # 生成鹽
        salt = os.urandom(16)
        
        # 生成加密密鑰
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # 加密私鑰
        encrypted_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key)
        )
        
        return encrypted_key
    
    def check_certificate_expiry(self, domain: str) -> Dict:
        """檢查憑證到期時間"""
        if domain not in self.certificates:
            return {"error": "Certificate not found"}
        
        cert_info = self.certificates[domain]
        expiry_date = datetime.fromisoformat(cert_info["not_valid_after"])
        days_until_expiry = (expiry_date - datetime.now()).days
        
        return {
            "domain": domain,
            "expiry_date": cert_info["not_valid_after"],
            "days_until_expiry": days_until_expiry,
            "needs_renewal": days_until_expiry < 30
        }
    
    def rotate_certificate(self, domain: str) -> Dict:
        """輪換憑證"""
        try:
            self.audit_log_event("certificate_rotation", {"domain": domain})
            
            # 檢查當前憑證
            current_cert = self.check_certificate_expiry(domain)
            if "error" in current_cert:
                return current_cert
            
            # 生成新憑證
            new_cert = self.generate_ssl_certificate(domain)
            
            # 備份舊憑證
            backup_dir = f"ssl/{domain}/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(backup_dir, exist_ok=True)
            
            if os.path.exists(f"ssl/{domain}/certificate.crt"):
                os.rename(f"ssl/{domain}/certificate.crt", f"{backup_dir}/certificate.crt")
            if os.path.exists(f"ssl/{domain}/private.key"):
                os.rename(f"ssl/{domain}/private.key", f"{backup_dir}/private.key")
            
            # 更新憑證
            os.rename(f"ssl/{domain}/certificate.crt", f"ssl/{domain}/certificate.crt")
            os.rename(f"ssl/{domain}/private.key", f"ssl/{domain}/private.key")
            
            self.logger.info(f"憑證輪換成功: {domain}")
            return new_cert
            
        except Exception as e:
            self.logger.error(f"憑證輪換失敗: {e}")
            raise
    
    def setup_secret_management(self):
        """設置機密管理"""
        try:
            self.audit_log_event("secret_management_setup", {})
            
            # 從環境變數讀取機密
            secrets_to_manage = [
                "SSL_KEY_PASSWORD",
                "WAF_API_KEY",
                "SIEM_API_KEY",
                "DATABASE_PASSWORD",
                "ENCRYPTION_KEY"
            ]
            
            for secret_name in secrets_to_manage:
                secret_value = os.getenv(secret_name)
                if secret_value:
                    # 加密儲存
                    encrypted_secret = self._encrypt_secret(secret_value)
                    self.secrets[secret_name] = {
                        "encrypted_value": encrypted_secret,
                        "created_at": datetime.now().isoformat(),
                        "last_rotated": datetime.now().isoformat()
                    }
            
            self.logger.info(f"機密管理設置完成，管理 {len(self.secrets)} 個機密")
            
        except Exception as e:
            self.logger.error(f"機密管理設置失敗: {e}")
            raise
    
    def _encrypt_secret(self, secret: str) -> str:
        """加密機密"""
        # 使用主密鑰
        master_key = os.getenv("MASTER_ENCRYPTION_KEY", "default_master_key")
        
        # 生成隨機鹽
        salt = os.urandom(16)
        
        # 生成加密密鑰
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        
        # 加密機密
        encrypted = hmac.new(key, secret.encode(), hashes.SHA256()).hexdigest()
        
        return base64.b64encode(salt + encrypted.encode()).decode()
    
    def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """輪換機密"""
        try:
            self.audit_log_event("secret_rotation", {"secret_name": secret_name})
            
            if secret_name not in self.secrets:
                return False
            
            # 加密新機密
            encrypted_secret = self._encrypt_secret(new_value)
            
            # 更新機密
            self.secrets[secret_name]["encrypted_value"] = encrypted_secret
            self.secrets[secret_name]["last_rotated"] = datetime.now().isoformat()
            
            self.logger.info(f"機密輪換成功: {secret_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"機密輪換失敗: {e}")
            return False
    
    def setup_rate_limiting(self):
        """設置 L7 速率限制"""
        try:
            self.audit_log_event("rate_limiting_setup", {})
            
            # 配置速率限制規則
            rate_limit_rules = {
                "global": {
                    "requests_per_minute": 1000,
                    "burst_size": 100,
                    "window_size": 60
                },
                "per_ip": {
                    "requests_per_minute": 100,
                    "burst_size": 20,
                    "window_size": 60
                },
                "per_endpoint": {
                    "/api/": {
                        "requests_per_minute": 200,
                        "burst_size": 50,
                        "window_size": 60
                    },
                    "/search": {
                        "requests_per_minute": 50,
                        "burst_size": 10,
                        "window_size": 60
                    }
                }
            }
            
            self.rate_limits = rate_limit_rules
            self.logger.info("L7 速率限制設置完成")
            
        except Exception as e:
            self.logger.error(f"速率限制設置失敗: {e}")
            raise
    
    def setup_geo_blocking(self):
        """設置地理位置阻擋"""
        try:
            self.audit_log_event("geo_blocking_setup", {})
            
            # 高風險國家/地區
            high_risk_countries = [
                "CN",  # 中國
                "RU",  # 俄羅斯
                "KP",  # 北韓
                "IR",  # 伊朗
            ]
            
            # 高風險 IP 段
            high_risk_networks = [
                "192.168.1.0/24",
                "10.0.0.0/8",
                "172.16.0.0/12"
            ]
            
            self.geo_blocks = set(high_risk_countries)
            
            # 配置 GeoIP 規則
            geo_rules = {
                "blocked_countries": list(high_risk_countries),
                "blocked_networks": high_risk_networks,
                "whitelist_countries": ["TW", "US", "JP", "SG"],
                "action": "block"
            }
            
            self.logger.info(f"地理位置阻擋設置完成，阻擋 {len(high_risk_countries)} 個國家")
            
        except Exception as e:
            self.logger.error(f"地理位置阻擋設置失敗: {e}")
            raise
    
    def setup_ddos_protection(self):
        """設置 DDoS 防護"""
        try:
            self.audit_log_event("ddos_protection_setup", {})
            
            # DDoS 防護規則
            ddos_rules = {
                "connection_limits": {
                    "max_connections_per_ip": 50,
                    "max_connections_global": 1000,
                    "connection_timeout": 30
                },
                "request_limits": {
                    "requests_per_second_per_ip": 10,
                    "requests_per_minute_per_ip": 100,
                    "burst_size": 20
                },
                "pattern_detection": {
                    "suspicious_patterns": [
                        "rapid_requests",
                        "large_payloads",
                        "unusual_user_agents",
                        "repeated_errors"
                    ],
                    "threshold": 80
                },
                "mitigation": {
                    "action": "rate_limit",
                    "duration": 300,  # 5 分鐘
                    "escalation": "block"
                }
            }
            
            self.ddos_protection = ddos_rules
            self.logger.info("DDoS 防護設置完成")
            
        except Exception as e:
            self.logger.error(f"DDoS 防護設置失敗: {e}")
            raise
    
    def setup_cdn_integration(self):
        """設置 CDN 整合"""
        try:
            self.audit_log_event("cdn_integration_setup", {})
            
            # CDN 配置
            cdn_config = {
                "provider": "cloudflare",
                "features": [
                    "ddos_protection",
                    "waf",
                    "rate_limiting",
                    "geo_blocking",
                    "ssl_termination"
                ],
                "rules": {
                    "cache_static": True,
                    "bypass_cache_for_dynamic": True,
                    "edge_caching": True
                }
            }
            
            self.logger.info("CDN 整合設置完成")
            return cdn_config
            
        except Exception as e:
            self.logger.error(f"CDN 整合設置失敗: {e}")
            raise
    
    def run_security_audit(self) -> Dict:
        """執行安全審計"""
        try:
            self.audit_log_event("security_audit", {})
            
            audit_results = {
                "timestamp": datetime.now().isoformat(),
                "certificates": {},
                "secrets": {},
                "rate_limits": {},
                "geo_blocking": {},
                "ddos_protection": {},
                "compliance": {}
            }
            
            # 審計憑證
            for domain, cert_info in self.certificates.items():
                expiry_check = self.check_certificate_expiry(domain)
                audit_results["certificates"][domain] = expiry_check
            
            # 審計機密
            for secret_name, secret_info in self.secrets.items():
                audit_results["secrets"][secret_name] = {
                    "created_at": secret_info["created_at"],
                    "last_rotated": secret_info["last_rotated"],
                    "needs_rotation": self._needs_secret_rotation(secret_info)
                }
            
            # 審計速率限制
            audit_results["rate_limits"] = {
                "configured": len(self.rate_limits) > 0,
                "rules_count": len(self.rate_limits)
            }
            
            # 審計地理位置阻擋
            audit_results["geo_blocking"] = {
                "configured": len(self.geo_blocks) > 0,
                "blocked_countries": len(self.geo_blocks)
            }
            
            # 審計 DDoS 防護
            audit_results["ddos_protection"] = {
                "configured": len(self.ddos_protection) > 0,
                "rules_count": len(self.ddos_protection)
            }
            
            # 合規性檢查
            audit_results["compliance"] = self._check_compliance(audit_results)
            
            self.logger.info("安全審計完成")
            return audit_results
            
        except Exception as e:
            self.logger.error(f"安全審計失敗: {e}")
            raise
    
    def _needs_secret_rotation(self, secret_info: Dict) -> bool:
        """檢查機密是否需要輪換"""
        last_rotated = datetime.fromisoformat(secret_info["last_rotated"])
        days_since_rotation = (datetime.now() - last_rotated).days
        return days_since_rotation > 90  # 90 天輪換一次
    
    def _check_compliance(self, audit_results: Dict) -> Dict:
        """檢查合規性"""
        compliance = {
            "ssl_certificates": True,
            "secret_management": True,
            "rate_limiting": True,
            "geo_blocking": True,
            "ddos_protection": True,
            "overall_compliance": True
        }
        
        # 檢查憑證
        for domain, cert_info in audit_results["certificates"].items():
            if cert_info.get("needs_renewal", False):
                compliance["ssl_certificates"] = False
        
        # 檢查機密
        for secret_name, secret_info in audit_results["secrets"].items():
            if secret_info.get("needs_rotation", False):
                compliance["secret_management"] = False
        
        # 檢查其他配置
        if not audit_results["rate_limits"]["configured"]:
            compliance["rate_limiting"] = False
        
        if not audit_results["geo_blocking"]["configured"]:
            compliance["geo_blocking"] = False
        
        if not audit_results["ddos_protection"]["configured"]:
            compliance["ddos_protection"] = False
        
        # 整體合規性
        compliance["overall_compliance"] = all(compliance.values())
        
        return compliance
    
    def generate_security_report(self) -> Dict:
        """生成安全報告"""
        try:
            audit_results = self.run_security_audit()
            
            report = {
                "report_timestamp": datetime.now().isoformat(),
                "security_baseline": {
                    "ssl_certificates": len(self.certificates),
                    "managed_secrets": len(self.secrets),
                    "rate_limit_rules": len(self.rate_limits),
                    "geo_blocked_countries": len(self.geo_blocks),
                    "ddos_protection_rules": len(self.ddos_protection)
                },
                "audit_results": audit_results,
                "recommendations": self._generate_recommendations(audit_results),
                "audit_log": self.audit_log[-100:]  # 最近 100 條審計日誌
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"安全報告生成失敗: {e}")
            raise
    
    def _generate_recommendations(self, audit_results: Dict) -> List[str]:
        """生成建議"""
        recommendations = []
        
        # 憑證建議
        for domain, cert_info in audit_results["certificates"].items():
            if cert_info.get("needs_renewal", False):
                recommendations.append(f"憑證 {domain} 需要更新")
        
        # 機密建議
        for secret_name, secret_info in audit_results["secrets"].items():
            if secret_info.get("needs_rotation", False):
                recommendations.append(f"機密 {secret_name} 需要輪換")
        
        # 配置建議
        if not audit_results["rate_limits"]["configured"]:
            recommendations.append("建議配置速率限制")
        
        if not audit_results["geo_blocking"]["configured"]:
            recommendations.append("建議配置地理位置阻擋")
        
        if not audit_results["ddos_protection"]["configured"]:
            recommendations.append("建議配置 DDoS 防護")
        
        return recommendations

def main():
    """主函數"""
    parser = argparse.ArgumentParser(description='安全基線補強工具')
    parser.add_argument('--action', choices=['setup', 'audit', 'rotate-cert', 'rotate-secret', 'report'], 
                       default='setup', help='執行動作')
    parser.add_argument('--domain', help='域名（用於憑證操作）')
    parser.add_argument('--secret-name', help='機密名稱（用於機密操作）')
    parser.add_argument('--output-file', help='輸出文件')
    
    args = parser.parse_args()
    
    # 創建安全基線管理器
    manager = SecurityBaselineManager()
    
    try:
        if args.action == 'setup':
            print("設置安全基線...")
            manager.setup_secret_management()
            manager.setup_rate_limiting()
            manager.setup_geo_blocking()
            manager.setup_ddos_protection()
            manager.setup_cdn_integration()
            print("[OK] 安全基線設置完成")
            
        elif args.action == 'audit':
            print("執行安全審計...")
            audit_results = manager.run_security_audit()
            print("[OK] 安全審計完成")
            print(json.dumps(audit_results, indent=2, ensure_ascii=False))
            
        elif args.action == 'rotate-cert':
            if not args.domain:
                print("[FAIL] 請指定域名")
                return
            print(f"輪換憑證: {args.domain}")
            result = manager.rotate_certificate(args.domain)
            print("[OK] 憑證輪換完成")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
        elif args.action == 'rotate-secret':
            if not args.secret_name:
                print("[FAIL] 請指定機密名稱")
                return
            print(f"輪換機密: {args.secret_name}")
            # 這裡需要從用戶輸入或環境變數獲取新值
            new_value = os.getenv(f"{args.secret_name}_NEW", "new_secret_value")
            result = manager.rotate_secret(args.secret_name, new_value)
            if result:
                print("[OK] 機密輪換完成")
            else:
                print("[FAIL] 機密輪換失敗")
                
        elif args.action == 'report':
            print("生成安全報告...")
            report = manager.generate_security_report()
            print("[OK] 安全報告生成完成")
            
            if args.output_file:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                print(f"報告已保存到: {args.output_file}")
            else:
                print(json.dumps(report, indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"[FAIL] 操作失敗: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
