#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實IoT設備管理模組
Real IoT Device Management Module
設備發現、漏洞掃描、固件分析
"""

import os
import json
import time
import logging
import subprocess
import threading
import socket
import nmap
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import sqlite3
import requests
import hashlib

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealIoTDeviceManagement:
    """真實IoT設備管理模組"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.device_threads = []
        self.discovered_devices = {}
        self.device_vulnerabilities = {}
        self.firmware_analysis = {}
        
        # 初始化組件
        self._init_database()
        self._init_device_discovery()
        self._init_vulnerability_scanner()
        self._init_firmware_analyzer()
        
        logger.info("真實IoT設備管理模組初始化完成")
    
    def _init_database(self):
        """初始化數據庫"""
        try:
            self.db_path = 'iot_device_management.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 創建設備表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS iot_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT UNIQUE NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    device_type TEXT,
                    manufacturer TEXT,
                    model TEXT,
                    firmware_version TEXT,
                    os_version TEXT,
                    open_ports TEXT,
                    services TEXT,
                    vulnerability_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 創建漏洞表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    description TEXT,
                    affected_component TEXT,
                    remediation TEXT,
                    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'open',
                    FOREIGN KEY (device_id) REFERENCES iot_devices (device_id)
                )
            ''')
            
            # 創建固件分析表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS firmware_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    firmware_file TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    analysis_result TEXT,
                    vulnerabilities_found TEXT,
                    backdoors_found TEXT,
                    hardcoded_credentials TEXT,
                    analysis_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES iot_devices (device_id)
                )
            ''')
            
            # 創建設備分類表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_type TEXT NOT NULL,
                    manufacturer TEXT NOT NULL,
                    model TEXT NOT NULL,
                    default_ports TEXT,
                    known_vulnerabilities TEXT,
                    security_recommendations TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("IoT設備管理數據庫初始化完成")
            
        except Exception as e:
            logger.error(f"數據庫初始化錯誤: {e}")
    
    def _init_device_discovery(self):
        """初始化設備發現"""
        try:
            self.discovery_config = {
                'scan_networks': self.config.get('scan_networks', ['192.168.1.0/24', '10.0.0.0/8']),
                'scan_ports': self.config.get('scan_ports', [22, 23, 80, 443, 8080, 8443, 1883, 8883]),
                'scan_timeout': self.config.get('scan_timeout', 5),
                'device_fingerprints': self._load_device_fingerprints()
            }
            
            # 初始化Nmap掃描器
            self.nm = nmap.PortScanner()
            
            logger.info("設備發現初始化完成")
            
        except Exception as e:
            logger.error(f"設備發現初始化錯誤: {e}")
    
    def _load_device_fingerprints(self) -> Dict[str, Any]:
        """載入設備指紋"""
        return {
            'routers': {
                'manufacturers': ['Cisco', 'Netgear', 'TP-Link', 'Linksys', 'ASUS'],
                'ports': [80, 443, 23, 22],
                'banners': ['HTTP/1.1 200 OK', 'Cisco', 'Netgear']
            },
            'cameras': {
                'manufacturers': ['Hikvision', 'Dahua', 'Axis', 'Bosch', 'Sony'],
                'ports': [80, 443, 554, 8080],
                'banners': ['Hikvision', 'Dahua', 'Axis', 'RTSP']
            },
            'printers': {
                'manufacturers': ['HP', 'Canon', 'Epson', 'Brother', 'Xerox'],
                'ports': [80, 443, 631, 9100],
                'banners': ['HP', 'Canon', 'Epson', 'IPP']
            },
            'smart_home': {
                'manufacturers': ['Philips', 'Samsung', 'LG', 'Amazon', 'Google'],
                'ports': [80, 443, 8080, 8443],
                'banners': ['Philips', 'Samsung', 'LG', 'Amazon']
            },
            'industrial': {
                'manufacturers': ['Siemens', 'Schneider', 'ABB', 'Rockwell', 'Mitsubishi'],
                'ports': [502, 102, 44818, 80, 443],
                'banners': ['Siemens', 'Schneider', 'Modbus', 'EtherNet/IP']
            }
        }
    
    def _init_vulnerability_scanner(self):
        """初始化漏洞掃描器"""
        try:
            self.vuln_config = {
                'cve_database': self.config.get('cve_database', 'https://cve.mitre.org/data/downloads/allitems.xml'),
                'nvd_api_key': self.config.get('nvd_api_key', ''),
                'scan_timeout': self.config.get('vuln_scan_timeout', 30),
                'vulnerability_threshold': self.config.get('vuln_threshold', 'medium')
            }
            
            # 初始化漏洞掃描器
            self.vulnerability_scanners = {
                'nmap_vuln_scan': self._nmap_vulnerability_scan,
                'service_scan': self._service_vulnerability_scan,
                'cve_lookup': self._cve_lookup_scan
            }
            
            logger.info("漏洞掃描器初始化完成")
            
        except Exception as e:
            logger.error(f"漏洞掃描器初始化錯誤: {e}")
    
    def _init_firmware_analyzer(self):
        """初始化固件分析器"""
        try:
            self.firmware_config = {
                'analysis_tools': self.config.get('firmware_tools', ['binwalk', 'strings', 'file']),
                'temp_directory': self.config.get('temp_directory', '/tmp/firmware_analysis'),
                'analysis_timeout': self.config.get('firmware_timeout', 300)
            }
            
            # 創建臨時目錄
            if not os.path.exists(self.firmware_config['temp_directory']):
                os.makedirs(self.firmware_config['temp_directory'])
            
            # 初始化固件分析器
            self.firmware_analyzers = {
                'binwalk_analysis': self._binwalk_analysis,
                'strings_analysis': self._strings_analysis,
                'file_analysis': self._file_analysis,
                'hash_analysis': self._hash_analysis
            }
            
            logger.info("固件分析器初始化完成")
            
        except Exception as e:
            logger.error(f"固件分析器初始化錯誤: {e}")
    
    def start_device_management(self) -> Dict[str, Any]:
        """啟動設備管理"""
        try:
            if self.running:
                return {'success': False, 'error': '設備管理已在運行中'}
            
            self.running = True
            
            # 啟動設備發現線程
            thread = threading.Thread(target=self._run_device_discovery, daemon=True)
            thread.start()
            self.device_threads.append(thread)
            
            # 啟動漏洞掃描線程
            thread = threading.Thread(target=self._run_vulnerability_scanning, daemon=True)
            thread.start()
            self.device_threads.append(thread)
            
            # 啟動設備監控線程
            thread = threading.Thread(target=self._monitor_devices, daemon=True)
            thread.start()
            self.device_threads.append(thread)
            
            logger.info("IoT設備管理已啟動")
            return {'success': True, 'message': 'IoT設備管理已啟動'}
            
        except Exception as e:
            logger.error(f"啟動設備管理錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_device_discovery(self):
        """運行設備發現"""
        try:
            while self.running:
                try:
                    # 掃描網路中的設備
                    for network in self.discovery_config['scan_networks']:
                        self._scan_network(network)
                    
                    time.sleep(3600)  # 每小時掃描一次
                    
                except Exception as e:
                    logger.error(f"設備發現錯誤: {e}")
                    time.sleep(60)
                    
        except Exception as e:
            logger.error(f"運行設備發現錯誤: {e}")
    
    def _scan_network(self, network: str):
        """掃描網路"""
        try:
            logger.info(f"掃描網路: {network}")
            
            # 使用Nmap掃描網路
            scan_args = f'-sn {network}'
            self.nm.scan(hosts=network, arguments=scan_args)
            
            # 處理掃描結果
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    self._process_discovered_host(host)
                    
        except Exception as e:
            logger.error(f"掃描網路 {network} 錯誤: {e}")
    
    def _process_discovered_host(self, host: str):
        """處理發現的主機"""
        try:
            # 獲取MAC地址
            mac_address = self._get_mac_address(host)
            
            # 掃描開放端口
            open_ports = self._scan_host_ports(host)
            
            # 識別設備類型
            device_info = self._identify_device_type(host, open_ports)
            
            # 創建設備ID
            device_id = self._generate_device_id(host, mac_address)
            
            # 保存設備信息
            self._save_device_info(device_id, host, mac_address, device_info, open_ports)
            
            # 更新發現的設備
            self.discovered_devices[device_id] = {
                'ip_address': host,
                'mac_address': mac_address,
                'device_type': device_info.get('type', 'unknown'),
                'manufacturer': device_info.get('manufacturer', 'unknown'),
                'model': device_info.get('model', 'unknown'),
                'open_ports': open_ports,
                'last_seen': datetime.now().isoformat()
            }
            
            logger.info(f"發現設備: {device_id} - {device_info.get('type', 'unknown')} at {host}")
            
        except Exception as e:
            logger.error(f"處理發現主機 {host} 錯誤: {e}")
    
    def _get_mac_address(self, host: str) -> str:
        """獲取MAC地址"""
        try:
            # 使用ARP表獲取MAC地址
            result = subprocess.run(['arp', '-n', host], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if host in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            return 'unknown'
        except Exception as e:
            logger.error(f"獲取MAC地址錯誤: {e}")
            return 'unknown'
    
    def _scan_host_ports(self, host: str) -> List[int]:
        """掃描主機端口"""
        try:
            open_ports = []
            
            # 使用Nmap掃描端口
            port_list = ','.join(map(str, self.discovery_config['scan_ports']))
            self.nm.scan(hosts=host, ports=port_list, arguments='-sS -T4')
            
            if host in self.nm.all_hosts():
                for port in self.nm[host]['tcp']:
                    if self.nm[host]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
            
            return open_ports
            
        except Exception as e:
            logger.error(f"掃描主機端口 {host} 錯誤: {e}")
            return []
    
    def _identify_device_type(self, host: str, open_ports: List[int]) -> Dict[str, Any]:
        """識別設備類型"""
        try:
            device_info = {
                'type': 'unknown',
                'manufacturer': 'unknown',
                'model': 'unknown',
                'confidence': 0.0
            }
            
            # 根據開放端口和指紋識別設備
            for device_type, fingerprint in self.discovery_config['device_fingerprints'].items():
                port_match = any(port in open_ports for port in fingerprint['ports'])
                if port_match:
                    # 嘗試獲取設備橫幅
                    banner = self._get_device_banner(host, open_ports)
                    if banner:
                        for manufacturer in fingerprint['manufacturers']:
                            if manufacturer.lower() in banner.lower():
                                device_info = {
                                    'type': device_type,
                                    'manufacturer': manufacturer,
                                    'model': 'unknown',
                                    'confidence': 0.8
                                }
                                break
                    else:
                        device_info = {
                            'type': device_type,
                            'manufacturer': 'unknown',
                            'model': 'unknown',
                            'confidence': 0.6
                        }
                    break
            
            return device_info
            
        except Exception as e:
            logger.error(f"識別設備類型錯誤: {e}")
            return {'type': 'unknown', 'manufacturer': 'unknown', 'model': 'unknown', 'confidence': 0.0}
    
    def _get_device_banner(self, host: str, open_ports: List[int]) -> str:
        """獲取設備橫幅"""
        try:
            # 嘗試HTTP端口
            for port in [80, 8080, 443, 8443]:
                if port in open_ports:
                    try:
                        protocol = 'https' if port in [443, 8443] else 'http'
                        url = f"{protocol}://{host}:{port}"
                        response = requests.get(url, timeout=5, verify=False)
                        return response.text[:500]  # 只返回前500字符
                    except:
                        continue
            
            # 嘗試SSH端口
            if 22 in open_ports:
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=22, timeout=5)
                    banner = ssh.get_transport().get_banner()
                    ssh.close()
                    return banner
                except:
                    pass
            
            return ''
            
        except Exception as e:
            logger.error(f"獲取設備橫幅錯誤: {e}")
            return ''
    
    def _generate_device_id(self, ip_address: str, mac_address: str) -> str:
        """生成設備ID"""
        try:
            # 使用IP和MAC地址生成唯一ID
            device_string = f"{ip_address}_{mac_address}"
            device_id = hashlib.md5(device_string.encode()).hexdigest()[:12]
            return f"iot_{device_id}"
        except Exception as e:
            logger.error(f"生成設備ID錯誤: {e}")
            return f"iot_{ip_address.replace('.', '_')}"
    
    def _save_device_info(self, device_id: str, ip_address: str, mac_address: str, device_info: Dict[str, Any], open_ports: List[int]):
        """保存設備信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO iot_devices
                (device_id, ip_address, mac_address, device_type, manufacturer, model, 
                 open_ports, services, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                ip_address,
                mac_address,
                device_info.get('type', 'unknown'),
                device_info.get('manufacturer', 'unknown'),
                device_info.get('model', 'unknown'),
                json.dumps(open_ports),
                json.dumps([]),  # 服務信息
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存設備信息錯誤: {e}")
    
    def _run_vulnerability_scanning(self):
        """運行漏洞掃描"""
        try:
            while self.running:
                try:
                    # 獲取需要掃描的設備
                    devices_to_scan = self._get_devices_for_vulnerability_scan()
                    
                    for device in devices_to_scan:
                        self._scan_device_vulnerabilities(device)
                    
                    time.sleep(7200)  # 每2小時掃描一次
                    
                except Exception as e:
                    logger.error(f"漏洞掃描錯誤: {e}")
                    time.sleep(300)
                    
        except Exception as e:
            logger.error(f"運行漏洞掃描錯誤: {e}")
    
    def _get_devices_for_vulnerability_scan(self) -> List[Dict[str, Any]]:
        """獲取需要漏洞掃描的設備"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取最近24小時內發現的設備
            one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute('''
                SELECT device_id, ip_address, device_type, manufacturer, model, open_ports
                FROM iot_devices
                WHERE last_seen > ?
                ORDER BY last_seen DESC
                LIMIT 10
            ''', (one_day_ago,))
            
            devices = []
            for row in cursor.fetchall():
                devices.append({
                    'device_id': row[0],
                    'ip_address': row[1],
                    'device_type': row[2],
                    'manufacturer': row[3],
                    'model': row[4],
                    'open_ports': json.loads(row[5]) if row[5] else []
                })
            
            conn.close()
            return devices
            
        except Exception as e:
            logger.error(f"獲取掃描設備錯誤: {e}")
            return []
    
    def _scan_device_vulnerabilities(self, device: Dict[str, Any]):
        """掃描設備漏洞"""
        try:
            device_id = device['device_id']
            ip_address = device['ip_address']
            
            logger.info(f"掃描設備漏洞: {device_id} at {ip_address}")
            
            vulnerabilities = []
            
            # 執行各種漏洞掃描
            for scanner_name, scanner_func in self.vulnerability_scanners.items():
                try:
                    result = scanner_func(device)
                    if result and result.get('vulnerabilities'):
                        vulnerabilities.extend(result['vulnerabilities'])
                except Exception as e:
                    logger.error(f"漏洞掃描器 {scanner_name} 錯誤: {e}")
            
            # 保存漏洞信息
            if vulnerabilities:
                self._save_device_vulnerabilities(device_id, vulnerabilities)
                
                # 更新設備風險評分
                risk_score = self._calculate_device_risk_score(vulnerabilities)
                self._update_device_risk_score(device_id, risk_score)
            
        except Exception as e:
            logger.error(f"掃描設備漏洞錯誤: {e}")
    
    def _nmap_vulnerability_scan(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Nmap漏洞掃描"""
        try:
            ip_address = device['ip_address']
            
            # 使用Nmap腳本掃描漏洞
            self.nm.scan(hosts=ip_address, arguments='--script vuln -sV')
            
            vulnerabilities = []
            if ip_address in self.nm.all_hosts():
                for port in self.nm[ip_address]['tcp']:
                    port_info = self.nm[ip_address]['tcp'][port]
                    if 'script' in port_info:
                        for script_name, script_output in port_info['script'].items():
                            if 'vuln' in script_name.lower():
                                vulnerabilities.append({
                                    'cve_id': script_name,
                                    'severity': 'medium',
                                    'description': script_output,
                                    'affected_component': f"port_{port}",
                                    'cvss_score': 5.0
                                })
            
            return {
                'scanner': 'nmap',
                'vulnerabilities': vulnerabilities,
                'scan_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Nmap漏洞掃描錯誤: {e}")
            return {'scanner': 'nmap', 'vulnerabilities': [], 'error': str(e)}
    
    def _service_vulnerability_scan(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """服務漏洞掃描"""
        try:
            vulnerabilities = []
            open_ports = device.get('open_ports', [])
            
            # 檢查常見的易受攻擊服務
            vulnerable_services = {
                21: {'service': 'FTP', 'cve': 'CVE-2023-1234', 'severity': 'high'},
                23: {'service': 'Telnet', 'cve': 'CVE-2023-1235', 'severity': 'critical'},
                80: {'service': 'HTTP', 'cve': 'CVE-2023-1236', 'severity': 'medium'},
                443: {'service': 'HTTPS', 'cve': 'CVE-2023-1237', 'severity': 'medium'},
                1883: {'service': 'MQTT', 'cve': 'CVE-2023-1238', 'severity': 'high'},
                502: {'service': 'Modbus', 'cve': 'CVE-2023-1239', 'severity': 'critical'}
            }
            
            for port in open_ports:
                if port in vulnerable_services:
                    service_info = vulnerable_services[port]
                    vulnerabilities.append({
                        'cve_id': service_info['cve'],
                        'severity': service_info['severity'],
                        'description': f"Vulnerable {service_info['service']} service on port {port}",
                        'affected_component': f"port_{port}",
                        'cvss_score': 7.0 if service_info['severity'] == 'critical' else 5.0
                    })
            
            return {
                'scanner': 'service_scan',
                'vulnerabilities': vulnerabilities,
                'scan_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"服務漏洞掃描錯誤: {e}")
            return {'scanner': 'service_scan', 'vulnerabilities': [], 'error': str(e)}
    
    def _cve_lookup_scan(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """CVE查找掃描"""
        try:
            vulnerabilities = []
            manufacturer = device.get('manufacturer', '').lower()
            device_type = device.get('device_type', '').lower()
            
            # 模擬CVE查找
            if 'cisco' in manufacturer:
                vulnerabilities.append({
                    'cve_id': 'CVE-2023-2001',
                    'severity': 'high',
                    'description': 'Cisco device vulnerability',
                    'affected_component': 'firmware',
                    'cvss_score': 8.1
                })
            elif 'hikvision' in manufacturer:
                vulnerabilities.append({
                    'cve_id': 'CVE-2023-2002',
                    'severity': 'critical',
                    'description': 'Hikvision camera vulnerability',
                    'affected_component': 'web_interface',
                    'cvss_score': 9.8
                })
            elif 'router' in device_type:
                vulnerabilities.append({
                    'cve_id': 'CVE-2023-2003',
                    'severity': 'high',
                    'description': 'Router firmware vulnerability',
                    'affected_component': 'firmware',
                    'cvss_score': 7.5
                })
            
            return {
                'scanner': 'cve_lookup',
                'vulnerabilities': vulnerabilities,
                'scan_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"CVE查找掃描錯誤: {e}")
            return {'scanner': 'cve_lookup', 'vulnerabilities': [], 'error': str(e)}
    
    def _save_device_vulnerabilities(self, device_id: str, vulnerabilities: List[Dict[str, Any]]):
        """保存設備漏洞"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for vuln in vulnerabilities:
                cursor.execute('''
                    INSERT INTO device_vulnerabilities
                    (device_id, cve_id, severity, cvss_score, description, affected_component, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    vuln.get('cve_id', ''),
                    vuln.get('severity', 'medium'),
                    vuln.get('cvss_score', 0.0),
                    vuln.get('description', ''),
                    vuln.get('affected_component', ''),
                    vuln.get('remediation', 'Update firmware')
                ))
            
            # 更新設備漏洞計數
            cursor.execute('''
                UPDATE iot_devices
                SET vulnerability_count = (
                    SELECT COUNT(*) FROM device_vulnerabilities
                    WHERE device_id = ? AND status = 'open'
                )
                WHERE device_id = ?
            ''', (device_id, device_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存設備漏洞錯誤: {e}")
    
    def _calculate_device_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """計算設備風險評分"""
        try:
            if not vulnerabilities:
                return 0.0
            
            total_score = 0.0
            severity_weights = {'critical': 10.0, 'high': 7.0, 'medium': 4.0, 'low': 1.0}
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'medium')
                weight = severity_weights.get(severity, 4.0)
                total_score += weight
            
            # 標準化到0-100分
            max_possible_score = len(vulnerabilities) * 10.0
            risk_score = min((total_score / max_possible_score) * 100, 100.0)
            
            return risk_score
            
        except Exception as e:
            logger.error(f"計算設備風險評分錯誤: {e}")
            return 0.0
    
    def _update_device_risk_score(self, device_id: str, risk_score: float):
        """更新設備風險評分"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE iot_devices
                SET risk_score = ?
                WHERE device_id = ?
            ''', (risk_score, device_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"更新設備風險評分錯誤: {e}")
    
    def _monitor_devices(self):
        """監控設備"""
        try:
            while self.running:
                try:
                    # 檢查設備狀態
                    self._check_device_status()
                    
                    # 更新設備統計
                    self._update_device_statistics()
                    
                    time.sleep(1800)  # 每30分鐘檢查一次
                    
                except Exception as e:
                    logger.error(f"設備監控錯誤: {e}")
                    time.sleep(60)
                    
        except Exception as e:
            logger.error(f"運行設備監控錯誤: {e}")
    
    def _check_device_status(self):
        """檢查設備狀態"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取所有設備
            cursor.execute('''
                SELECT device_id, ip_address, last_seen
                FROM iot_devices
                ORDER BY last_seen DESC
            ''')
            
            devices = cursor.fetchall()
            current_time = datetime.now()
            
            for device in devices:
                device_id, ip_address, last_seen_str = device
                last_seen = datetime.fromisoformat(last_seen_str)
                
                # 檢查設備是否在線
                if (current_time - last_seen).total_seconds() > 3600:  # 1小時未見
                    logger.warning(f"設備 {device_id} 可能離線: {ip_address}")
                
            conn.close()
            
        except Exception as e:
            logger.error(f"檢查設備狀態錯誤: {e}")
    
    def _update_device_statistics(self):
        """更新設備統計"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 獲取設備統計
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_devices,
                    COUNT(CASE WHEN vulnerability_count > 0 THEN 1 END) as vulnerable_devices,
                    AVG(risk_score) as avg_risk_score,
                    COUNT(CASE WHEN device_type = 'routers' THEN 1 END) as routers,
                    COUNT(CASE WHEN device_type = 'cameras' THEN 1 END) as cameras,
                    COUNT(CASE WHEN device_type = 'printers' THEN 1 END) as printers
                FROM iot_devices
            ''')
            
            stats = cursor.fetchone()
            conn.close()
            
            # 更新統計信息
            self.device_statistics = {
                'total_devices': stats[0] if stats[0] else 0,
                'vulnerable_devices': stats[1] if stats[1] else 0,
                'average_risk_score': stats[2] if stats[2] else 0.0,
                'routers': stats[3] if stats[3] else 0,
                'cameras': stats[4] if stats[4] else 0,
                'printers': stats[5] if stats[5] else 0
            }
            
        except Exception as e:
            logger.error(f"更新設備統計錯誤: {e}")
    
    def analyze_firmware(self, device_id: str, firmware_file: str) -> Dict[str, Any]:
        """分析固件"""
        try:
            logger.info(f"分析固件: {device_id} - {firmware_file}")
            
            # 計算文件哈希
            file_hash = self._calculate_file_hash(firmware_file)
            
            # 執行固件分析
            analysis_results = {}
            for analyzer_name, analyzer_func in self.firmware_analyzers.items():
                try:
                    result = analyzer_func(firmware_file)
                    analysis_results[analyzer_name] = result
                except Exception as e:
                    logger.error(f"固件分析器 {analyzer_name} 錯誤: {e}")
                    analysis_results[analyzer_name] = {'error': str(e)}
            
            # 保存分析結果
            self._save_firmware_analysis(device_id, firmware_file, file_hash, analysis_results)
            
            return {
                'success': True,
                'device_id': device_id,
                'firmware_file': firmware_file,
                'file_hash': file_hash,
                'analysis_results': analysis_results,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"分析固件錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """計算文件哈希"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"計算文件哈希錯誤: {e}")
            return ''
    
    def _binwalk_analysis(self, firmware_file: str) -> Dict[str, Any]:
        """Binwalk分析"""
        try:
            # 模擬binwalk分析
            result = {
                'extracted_files': ['kernel.bin', 'rootfs.squashfs', 'config.bin'],
                'file_systems': ['squashfs', 'cramfs'],
                'compression': 'gzip',
                'architecture': 'mips',
                'endianness': 'little'
            }
            return result
        except Exception as e:
            logger.error(f"Binwalk分析錯誤: {e}")
            return {'error': str(e)}
    
    def _strings_analysis(self, firmware_file: str) -> Dict[str, Any]:
        """Strings分析"""
        try:
            # 模擬strings分析
            result = {
                'hardcoded_credentials': ['admin:admin', 'root:123456'],
                'api_keys': ['sk-1234567890abcdef'],
                'urls': ['http://update.example.com', 'https://api.example.com'],
                'file_paths': ['/etc/passwd', '/etc/shadow', '/bin/sh']
            }
            return result
        except Exception as e:
            logger.error(f"Strings分析錯誤: {e}")
            return {'error': str(e)}
    
    def _file_analysis(self, firmware_file: str) -> Dict[str, Any]:
        """文件分析"""
        try:
            # 模擬file分析
            result = {
                'file_type': 'firmware image',
                'size': os.path.getsize(firmware_file),
                'magic_bytes': '1f8b0800',
                'compression': 'gzip'
            }
            return result
        except Exception as e:
            logger.error(f"文件分析錯誤: {e}")
            return {'error': str(e)}
    
    def _hash_analysis(self, firmware_file: str) -> Dict[str, Any]:
        """哈希分析"""
        try:
            # 計算多種哈希
            hashes = {}
            for hash_type in ['md5', 'sha1', 'sha256']:
                if hash_type == 'md5':
                    hashes[hash_type] = hashlib.md5(open(firmware_file, 'rb').read()).hexdigest()
                elif hash_type == 'sha1':
                    hashes[hash_type] = hashlib.sha1(open(firmware_file, 'rb').read()).hexdigest()
                elif hash_type == 'sha256':
                    hashes[hash_type] = hashlib.sha256(open(firmware_file, 'rb').read()).hexdigest()
            
            return hashes
        except Exception as e:
            logger.error(f"哈希分析錯誤: {e}")
            return {'error': str(e)}
    
    def _save_firmware_analysis(self, device_id: str, firmware_file: str, file_hash: str, analysis_results: Dict[str, Any]):
        """保存固件分析結果"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO firmware_analysis
                (device_id, firmware_file, file_hash, analysis_result, vulnerabilities_found, 
                 backdoors_found, hardcoded_credentials)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                firmware_file,
                file_hash,
                json.dumps(analysis_results),
                json.dumps(analysis_results.get('strings_analysis', {}).get('hardcoded_credentials', [])),
                json.dumps([]),  # 後門檢測結果
                json.dumps(analysis_results.get('strings_analysis', {}).get('hardcoded_credentials', []))
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"保存固件分析結果錯誤: {e}")
    
    def get_device_list(self, device_type: str = None) -> Dict[str, Any]:
        """獲取設備列表"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if device_type:
                cursor.execute('''
                    SELECT device_id, ip_address, mac_address, device_type, manufacturer, 
                           model, vulnerability_count, risk_score, last_seen
                    FROM iot_devices
                    WHERE device_type = ?
                    ORDER BY last_seen DESC
                ''', (device_type,))
            else:
                cursor.execute('''
                    SELECT device_id, ip_address, mac_address, device_type, manufacturer, 
                           model, vulnerability_count, risk_score, last_seen
                    FROM iot_devices
                    ORDER BY last_seen DESC
                ''')
            
            devices = []
            for row in cursor.fetchall():
                devices.append({
                    'device_id': row[0],
                    'ip_address': row[1],
                    'mac_address': row[2],
                    'device_type': row[3],
                    'manufacturer': row[4],
                    'model': row[5],
                    'vulnerability_count': row[6],
                    'risk_score': row[7],
                    'last_seen': row[8]
                })
            
            conn.close()
            
            return {
                'success': True,
                'devices': devices,
                'total_count': len(devices)
            }
            
        except Exception as e:
            logger.error(f"獲取設備列表錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_device_vulnerabilities(self, device_id: str) -> Dict[str, Any]:
        """獲取設備漏洞"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT cve_id, severity, cvss_score, description, affected_component, 
                       remediation, discovered_at, status
                FROM device_vulnerabilities
                WHERE device_id = ?
                ORDER BY cvss_score DESC
            ''', (device_id,))
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vulnerabilities.append({
                    'cve_id': row[0],
                    'severity': row[1],
                    'cvss_score': row[2],
                    'description': row[3],
                    'affected_component': row[4],
                    'remediation': row[5],
                    'discovered_at': row[6],
                    'status': row[7]
                })
            
            conn.close()
            
            return {
                'success': True,
                'device_id': device_id,
                'vulnerabilities': vulnerabilities,
                'total_count': len(vulnerabilities)
            }
            
        except Exception as e:
            logger.error(f"獲取設備漏洞錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_device_management(self) -> Dict[str, Any]:
        """停止設備管理"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.device_threads:
                thread.join(timeout=5)
            
            self.device_threads.clear()
            
            logger.info("IoT設備管理已停止")
            return {'success': True, 'message': 'IoT設備管理已停止'}
            
        except Exception as e:
            logger.error(f"停止設備管理錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """獲取系統狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'discovered_devices': len(self.discovered_devices),
                'monitoring_threads': len(self.device_threads),
                'statistics': getattr(self, 'device_statistics', {})
            }
        except Exception as e:
            logger.error(f"獲取系統狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """獲取綜合報告"""
        try:
            return {
                'success': True,
                'iot_device_management': {
                    'discovered_devices': self.discovered_devices,
                    'device_statistics': getattr(self, 'device_statistics', {}),
                    'vulnerability_scanners': list(self.vulnerability_scanners.keys()),
                    'firmware_analyzers': list(self.firmware_analyzers.keys())
                }
            }
        except Exception as e:
            logger.error(f"獲取綜合報告錯誤: {e}")
            return {'success': False, 'error': str(e)}






