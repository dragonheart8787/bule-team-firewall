#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實數位鑑識系統
Real Digital Forensics System
"""

import os
import sys
import json
import time
import hashlib
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import psutil
import shutil
import tempfile
import zipfile

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealDigitalForensics:
    """真實數位鑑識系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.forensics_threads = []
        self.evidence_chain = []
        self.analysis_results = {}
        self.forensics_dir = config.get('forensics_dir', 'forensics')
        self.temp_dir = config.get('temp_dir', 'temp_forensics')
        
        # 創建必要目錄
        self._create_directories()
        
        # 初始化鑑識工具
        self._init_forensics_tools()
        
        logger.info("真實數位鑑識系統初始化完成")
    
    def _create_directories(self):
        """創建必要目錄"""
        try:
            directories = [self.forensics_dir, self.temp_dir, 'evidence', 'reports']
            for directory in directories:
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    logger.info(f"創建目錄: {directory}")
        except Exception as e:
            logger.error(f"創建目錄錯誤: {e}")
    
    def _init_forensics_tools(self):
        """初始化鑑識工具"""
        try:
            self.forensics_tools = {
                'file_analysis': True,
                'memory_analysis': True,
                'network_analysis': True,
                'registry_analysis': os.name == 'nt',
                'log_analysis': True,
                'timeline_analysis': True
            }
            
            logger.info("鑑識工具初始化完成")
            
        except Exception as e:
            logger.error(f"鑑識工具初始化錯誤: {e}")
    
    def start_forensics(self) -> Dict[str, Any]:
        """開始數位鑑識"""
        try:
            if self.running:
                return {'success': False, 'error': '鑑識已在運行中'}
            
            self.running = True
            
            # 啟動鑑識線程
            self._start_evidence_collection()
            self._start_analysis_engine()
            self._start_timeline_analysis()
            
            logger.info("真實數位鑑識已啟動")
            return {'success': True, 'message': '數位鑑識已啟動'}
            
        except Exception as e:
            logger.error(f"啟動鑑識錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_evidence_collection(self):
        """啟動證據收集"""
        def collect_evidence():
            logger.info("證據收集已啟動")
            
            while self.running:
                try:
                    # 收集系統證據
                    self._collect_system_evidence()
                    
                    # 收集文件證據
                    self._collect_file_evidence()
                    
                    # 收集網路證據
                    self._collect_network_evidence()
                    
                    time.sleep(300)  # 每5分鐘收集一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"證據收集錯誤: {e}")
                    break
        
        thread = threading.Thread(target=collect_evidence, daemon=True)
        thread.start()
        self.forensics_threads.append(thread)
    
    def _collect_system_evidence(self):
        """收集系統證據"""
        try:
            evidence_id = f"SYS_{int(time.time())}"
            evidence_dir = os.path.join(self.forensics_dir, evidence_id)
            os.makedirs(evidence_dir, exist_ok=True)
            
            # 收集系統信息
            system_info = {
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                'platform': sys.platform,
                'architecture': os.uname().machine if hasattr(os, 'uname') else 'unknown',
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'current_time': datetime.now().isoformat(),
                'uptime': time.time() - psutil.boot_time(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/')._asdict() if os.name != 'nt' else psutil.disk_usage('C:\\')._asdict()
            }
            
            # 保存系統信息
            with open(os.path.join(evidence_dir, 'system_info.json'), 'w', encoding='utf-8') as f:
                json.dump(system_info, f, indent=2, ensure_ascii=False)
            
            # 收集進程信息
            self._collect_process_evidence(evidence_dir)
            
            # 收集服務信息
            self._collect_service_evidence(evidence_dir)
            
            # 收集用戶信息
            self._collect_user_evidence(evidence_dir)
            
            logger.info(f"系統證據已收集: {evidence_id}")
            
        except Exception as e:
            logger.error(f"收集系統證據錯誤: {e}")
    
    def _collect_process_evidence(self, evidence_dir: str):
        """收集進程證據"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'memory_info', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cmdline': proc_info['cmdline'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                        'memory_rss': proc_info['memory_info'].rss if proc_info['memory_info'] else 0,
                        'memory_vms': proc_info['memory_info'].vms if proc_info['memory_info'] else 0,
                        'cpu_percent': proc_info['cpu_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            with open(os.path.join(evidence_dir, 'processes.json'), 'w', encoding='utf-8') as f:
                json.dump(processes, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"收集進程證據錯誤: {e}")
    
    def _collect_service_evidence(self, evidence_dir: str):
        """收集服務證據"""
        try:
            if os.name == 'nt':  # Windows
                # 使用 sc 命令獲取服務信息
                result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    with open(os.path.join(evidence_dir, 'services.txt'), 'w', encoding='utf-8') as f:
                        f.write(result.stdout)
            else:  # Linux
                # 使用 systemctl 獲取服務信息
                result = subprocess.run(['systemctl', 'list-units', '--type=service'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    with open(os.path.join(evidence_dir, 'services.txt'), 'w', encoding='utf-8') as f:
                        f.write(result.stdout)
                        
        except Exception as e:
            logger.error(f"收集服務證據錯誤: {e}")
    
    def _collect_user_evidence(self, evidence_dir: str):
        """收集用戶證據"""
        try:
            users = []
            for user in psutil.users():
                users.append({
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat(),
                    'pid': user.pid
                })
            
            with open(os.path.join(evidence_dir, 'users.json'), 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"收集用戶證據錯誤: {e}")
    
    def _collect_file_evidence(self):
        """收集文件證據"""
        try:
            evidence_id = f"FILE_{int(time.time())}"
            evidence_dir = os.path.join(self.forensics_dir, evidence_id)
            os.makedirs(evidence_dir, exist_ok=True)
            
            # 掃描關鍵目錄
            critical_dirs = [
                'C:\\Windows\\System32',
                'C:\\Windows\\SysWOW64',
                'C:\\Program Files',
                'C:\\Program Files (x86)',
                '/bin', '/sbin', '/usr/bin', '/usr/sbin'
            ]
            
            file_evidence = []
            for directory in critical_dirs:
                if os.path.exists(directory):
                    files = self._scan_directory_for_evidence(directory)
                    file_evidence.extend(files)
            
            # 保存文件證據
            with open(os.path.join(evidence_dir, 'file_evidence.json'), 'w', encoding='utf-8') as f:
                json.dump(file_evidence, f, indent=2, ensure_ascii=False)
            
            logger.info(f"文件證據已收集: {evidence_id}")
            
        except Exception as e:
            logger.error(f"收集文件證據錯誤: {e}")
    
    def _scan_directory_for_evidence(self, directory: str) -> List[Dict[str, Any]]:
        """掃描目錄收集證據"""
        try:
            files = []
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        stat = os.stat(file_path)
                        file_info = {
                            'path': file_path,
                            'name': filename,
                            'size': stat.st_size,
                            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                            'hash': self._calculate_file_hash(file_path)
                        }
                        files.append(file_info)
                    except (OSError, PermissionError):
                        continue
            return files
        except Exception as e:
            logger.error(f"掃描目錄錯誤: {e}")
            return []
    
    def _collect_network_evidence(self):
        """收集網路證據"""
        try:
            evidence_id = f"NET_{int(time.time())}"
            evidence_dir = os.path.join(self.forensics_dir, evidence_id)
            os.makedirs(evidence_dir, exist_ok=True)
            
            # 收集網路連接
            connections = psutil.net_connections(kind='inet')
            network_evidence = []
            
            for conn in connections:
                network_evidence.append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                    'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                })
            
            # 保存網路證據
            with open(os.path.join(evidence_dir, 'network_evidence.json'), 'w', encoding='utf-8') as f:
                json.dump(network_evidence, f, indent=2, ensure_ascii=False)
            
            # 收集路由表
            self._collect_routing_table(evidence_dir)
            
            # 收集 ARP 表
            self._collect_arp_table(evidence_dir)
            
            logger.info(f"網路證據已收集: {evidence_id}")
            
        except Exception as e:
            logger.error(f"收集網路證據錯誤: {e}")
    
    def _collect_routing_table(self, evidence_dir: str):
        """收集路由表"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=30)
            else:  # Linux
                result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                with open(os.path.join(evidence_dir, 'routing_table.txt'), 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                    
        except Exception as e:
            logger.error(f"收集路由表錯誤: {e}")
    
    def _collect_arp_table(self, evidence_dir: str):
        """收集 ARP 表"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
            else:  # Linux
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                with open(os.path.join(evidence_dir, 'arp_table.txt'), 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                    
        except Exception as e:
            logger.error(f"收集 ARP 表錯誤: {e}")
    
    def _start_analysis_engine(self):
        """啟動分析引擎"""
        def analyze_evidence():
            logger.info("分析引擎已啟動")
            
            while self.running:
                try:
                    # 分析收集的證據
                    self._analyze_collected_evidence()
                    
                    time.sleep(600)  # 每10分鐘分析一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"分析引擎錯誤: {e}")
                    break
        
        thread = threading.Thread(target=analyze_evidence, daemon=True)
        thread.start()
        self.forensics_threads.append(thread)
    
    def _analyze_collected_evidence(self):
        """分析收集的證據"""
        try:
            # 分析文件證據
            self._analyze_file_evidence()
            
            # 分析進程證據
            self._analyze_process_evidence()
            
            # 分析網路證據
            self._analyze_network_evidence()
            
            # 分析時間線
            self._analyze_timeline()
            
        except Exception as e:
            logger.error(f"分析證據錯誤: {e}")
    
    def _analyze_file_evidence(self):
        """分析文件證據"""
        try:
            # 查找可疑文件
            suspicious_files = []
            
            # 掃描 forensics 目錄中的文件證據
            for evidence_dir in os.listdir(self.forensics_dir):
                evidence_path = os.path.join(self.forensics_dir, evidence_dir)
                if os.path.isdir(evidence_path):
                    file_evidence_path = os.path.join(evidence_path, 'file_evidence.json')
                    if os.path.exists(file_evidence_path):
                        with open(file_evidence_path, 'r', encoding='utf-8') as f:
                            file_evidence = json.load(f)
                        
                        for file_info in file_evidence:
                            if self._is_suspicious_file(file_info):
                                suspicious_files.append(file_info)
            
            if suspicious_files:
                self.analysis_results['suspicious_files'] = suspicious_files
                logger.warning(f"發現 {len(suspicious_files)} 個可疑文件")
                
        except Exception as e:
            logger.error(f"分析文件證據錯誤: {e}")
    
    def _is_suspicious_file(self, file_info: Dict[str, Any]) -> bool:
        """檢查是否為可疑文件"""
        try:
            file_path = file_info['path'].lower()
            filename = file_info['name'].lower()
            
            # 檢查可疑擴展名
            suspicious_extensions = ['.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js']
            if any(filename.endswith(ext) for ext in suspicious_extensions):
                return True
            
            # 檢查可疑路徑
            suspicious_paths = ['temp', 'appdata', 'users', 'downloads']
            if any(path in file_path for path in suspicious_paths):
                return True
            
            # 檢查異常文件大小
            if file_info['size'] < 1024 and any(filename.endswith(ext) for ext in ['.exe', '.dll']):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"檢查可疑文件錯誤: {e}")
            return False
    
    def _analyze_process_evidence(self):
        """分析進程證據"""
        try:
            suspicious_processes = []
            
            # 掃描 forensics 目錄中的進程證據
            for evidence_dir in os.listdir(self.forensics_dir):
                evidence_path = os.path.join(self.forensics_dir, evidence_dir)
                if os.path.isdir(evidence_path):
                    process_evidence_path = os.path.join(evidence_path, 'processes.json')
                    if os.path.exists(process_evidence_path):
                        with open(process_evidence_path, 'r', encoding='utf-8') as f:
                            process_evidence = json.load(f)
                        
                        for proc_info in process_evidence:
                            if self._is_suspicious_process(proc_info):
                                suspicious_processes.append(proc_info)
            
            if suspicious_processes:
                self.analysis_results['suspicious_processes'] = suspicious_processes
                logger.warning(f"發現 {len(suspicious_processes)} 個可疑進程")
                
        except Exception as e:
            logger.error(f"分析進程證據錯誤: {e}")
    
    def _is_suspicious_process(self, proc_info: Dict[str, Any]) -> bool:
        """檢查是否為可疑進程"""
        try:
            name = proc_info['name'].lower()
            cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
            
            # 檢查可疑進程名稱
            suspicious_names = ['nc', 'netcat', 'ncat', 'socat', 'wget', 'curl', 'powershell']
            if any(susp in name for susp in suspicious_names):
                return True
            
            # 檢查可疑命令行
            suspicious_patterns = [
                r'-e\s+\w+',  # 執行命令
                r'-c\s+\w+',  # 執行命令
                r'powershell.*-enc',  # PowerShell 編碼命令
                r'cmd.*\/c'   # CMD 執行命令
            ]
            
            import re
            for pattern in suspicious_patterns:
                if re.search(pattern, cmdline):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"檢查可疑進程錯誤: {e}")
            return False
    
    def _analyze_network_evidence(self):
        """分析網路證據"""
        try:
            suspicious_connections = []
            
            # 掃描 forensics 目錄中的網路證據
            for evidence_dir in os.listdir(self.forensics_dir):
                evidence_path = os.path.join(self.forensics_dir, evidence_dir)
                if os.path.isdir(evidence_path):
                    network_evidence_path = os.path.join(evidence_path, 'network_evidence.json')
                    if os.path.exists(network_evidence_path):
                        with open(network_evidence_path, 'r', encoding='utf-8') as f:
                            network_evidence = json.load(f)
                        
                        for conn_info in network_evidence:
                            if self._is_suspicious_connection(conn_info):
                                suspicious_connections.append(conn_info)
            
            if suspicious_connections:
                self.analysis_results['suspicious_connections'] = suspicious_connections
                logger.warning(f"發現 {len(suspicious_connections)} 個可疑連接")
                
        except Exception as e:
            logger.error(f"分析網路證據錯誤: {e}")
    
    def _is_suspicious_connection(self, conn_info: Dict[str, Any]) -> bool:
        """檢查是否為可疑連接"""
        try:
            if not conn_info['raddr']:
                return False
            
            # 解析遠端地址
            remote_ip, remote_port = conn_info['raddr'].split(':')
            remote_port = int(remote_port)
            
            # 檢查可疑端口
            suspicious_ports = [4444, 8080, 9999, 31337, 12345, 54321]
            if remote_port in suspicious_ports:
                return True
            
            # 檢查可疑 IP 範圍
            if remote_ip.startswith('192.168.') or remote_ip.startswith('10.') or remote_ip.startswith('172.'):
                return False  # 內網 IP 通常不視為可疑
            
            return False
            
        except Exception as e:
            logger.error(f"檢查可疑連接錯誤: {e}")
            return False
    
    def _start_timeline_analysis(self):
        """啟動時間線分析"""
        def analyze_timeline():
            logger.info("時間線分析已啟動")
            
            while self.running:
                try:
                    # 分析時間線
                    self._analyze_timeline()
                    
                    time.sleep(1800)  # 每30分鐘分析一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"時間線分析錯誤: {e}")
                    break
        
        thread = threading.Thread(target=analyze_timeline, daemon=True)
        thread.start()
        self.forensics_threads.append(thread)
    
    def _analyze_timeline(self):
        """分析時間線"""
        try:
            timeline_events = []
            
            # 收集所有時間線事件
            for evidence_dir in os.listdir(self.forensics_dir):
                evidence_path = os.path.join(self.forensics_dir, evidence_dir)
                if os.path.isdir(evidence_path):
                    # 收集文件時間線
                    file_evidence_path = os.path.join(evidence_path, 'file_evidence.json')
                    if os.path.exists(file_evidence_path):
                        with open(file_evidence_path, 'r', encoding='utf-8') as f:
                            file_evidence = json.load(f)
                        
                        for file_info in file_evidence:
                            timeline_events.append({
                                'timestamp': file_info['modified'],
                                'event_type': 'FILE_MODIFIED',
                                'description': f"文件修改: {file_info['name']}",
                                'details': file_info
                            })
            
            # 按時間排序
            timeline_events.sort(key=lambda x: x['timestamp'])
            
            # 分析時間模式
            self._analyze_timeline_patterns(timeline_events)
            
            self.analysis_results['timeline'] = timeline_events
            
        except Exception as e:
            logger.error(f"分析時間線錯誤: {e}")
    
    def _analyze_timeline_patterns(self, timeline_events: List[Dict[str, Any]]):
        """分析時間線模式"""
        try:
            # 分析短時間內的大量活動
            if len(timeline_events) > 100:
                # 檢查是否有短時間內的大量文件修改
                recent_events = [event for event in timeline_events 
                               if datetime.now() - datetime.fromisoformat(event['timestamp']) < timedelta(hours=1)]
                
                if len(recent_events) > 50:
                    logger.warning(f"檢測到短時間內大量活動: {len(recent_events)} 個事件")
                    
        except Exception as e:
            logger.error(f"分析時間線模式錯誤: {e}")
    
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
            return ""
    
    def stop_forensics(self) -> Dict[str, Any]:
        """停止數位鑑識"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.forensics_threads:
                thread.join(timeout=5)
            
            self.forensics_threads.clear()
            
            logger.info("數位鑑識已停止")
            return {'success': True, 'message': '鑑識已停止'}
            
        except Exception as e:
            logger.error(f"停止鑑識錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_forensics_status(self) -> Dict[str, Any]:
        """獲取鑑識狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'evidence_collected': len(os.listdir(self.forensics_dir)) if os.path.exists(self.forensics_dir) else 0,
                'analysis_results': self.analysis_results,
                'tools_available': self.forensics_tools
            }
        except Exception as e:
            logger.error(f"獲取鑑識狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_forensics_report(self) -> Dict[str, Any]:
        """獲取鑑識報告"""
        try:
            return {
                'success': True,
                'analysis_results': self.analysis_results,
                'evidence_summary': self._get_evidence_summary(),
                'recommendations': self._generate_recommendations()
            }
        except Exception as e:
            logger.error(f"獲取鑑識報告錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_evidence_summary(self) -> Dict[str, Any]:
        """獲取證據摘要"""
        try:
            evidence_count = 0
            if os.path.exists(self.forensics_dir):
                evidence_count = len([d for d in os.listdir(self.forensics_dir) 
                                    if os.path.isdir(os.path.join(self.forensics_dir, d))])
            
            return {
                'total_evidence_sets': evidence_count,
                'forensics_directory': self.forensics_dir,
                'analysis_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"獲取證據摘要錯誤: {e}")
            return {}
    
    def _generate_recommendations(self) -> List[str]:
        """生成建議"""
        try:
            recommendations = []
            
            if 'suspicious_files' in self.analysis_results:
                recommendations.append("發現可疑文件，建議進行進一步分析")
            
            if 'suspicious_processes' in self.analysis_results:
                recommendations.append("發現可疑進程，建議終止並分析")
            
            if 'suspicious_connections' in self.analysis_results:
                recommendations.append("發現可疑網路連接，建議封鎖相關 IP")
            
            if not recommendations:
                recommendations.append("未發現明顯的可疑活動")
            
            return recommendations
        except Exception as e:
            logger.error(f"生成建議錯誤: {e}")
            return ["分析過程中發生錯誤"]


def main():
    """主函數"""
    config = {
        'forensics_dir': 'forensics',
        'temp_dir': 'temp_forensics',
        'log_level': 'INFO'
    }
    
    forensics = RealDigitalForensics(config)
    
    try:
        # 啟動鑑識
        result = forensics.start_forensics()
        if result['success']:
            print("✅ 真實數位鑑識系統已啟動")
            print("按 Ctrl+C 停止鑑識")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止鑑識...")
        forensics.stop_forensics()
        print("✅ 鑑識已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()

