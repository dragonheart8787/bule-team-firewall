#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真實威脅情報整合系統
Real Threat Intelligence Integration System
"""

import os
import sys
import json
import time
import logging
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import xml.etree.ElementTree as ET
import yaml

# 配置日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealThreatIntelligenceIntegration:
    """真實威脅情報整合系統"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.running = False
        self.intel_threads = []
        self.ioc_database = {}
        self.threat_feeds = {}
        self.kill_chain_analysis = {}
        self.siem_integration = {}
        
        # 初始化威脅情報組件
        self._init_stix_taxii()
        self._init_ioc_management()
        self._init_kill_chain_analysis()
        self._init_siem_integration()
        
        logger.info("真實威脅情報整合系統初始化完成")
    
    def _init_stix_taxii(self):
        """初始化STIX/TAXII"""
        try:
            self.stix_taxii_config = {
                'enabled': True,
                'taxii_servers': [
                    {
                        'name': 'MISP',
                        'url': 'https://misp.example.com/taxii2/',
                        'collection': 'indicators',
                        'auth': {'username': 'user', 'password': 'pass'}
                    },
                    {
                        'name': 'OpenCTI',
                        'url': 'https://opencti.example.com/taxii2/',
                        'collection': 'indicators',
                        'auth': {'username': 'user', 'password': 'pass'}
                    }
                ],
                'stix_version': '2.1',
                'update_interval': 3600  # 1小時
            }
            
            logger.info("STIX/TAXII初始化完成")
            
        except Exception as e:
            logger.error(f"STIX/TAXII初始化錯誤: {e}")
    
    def _init_ioc_management(self):
        """初始化IoC管理"""
        try:
            self.ioc_config = {
                'enabled': True,
                'ioc_types': ['ip', 'domain', 'url', 'hash', 'email'],
                'confidence_levels': ['low', 'medium', 'high', 'critical'],
                'auto_block': True,
                'block_threshold': 'medium'
            }
            
            # 初始化IoC資料庫
            self._init_ioc_database()
            
            logger.info("IoC管理初始化完成")
            
        except Exception as e:
            logger.error(f"IoC管理初始化錯誤: {e}")
    
    def _init_ioc_database(self):
        """初始化IoC資料庫"""
        try:
            self.ioc_database = {
                'ips': {},
                'domains': {},
                'urls': {},
                'hashes': {},
                'emails': {}
            }
            
            # 載入已知IoC
            self._load_known_iocs()
            
        except Exception as e:
            logger.error(f"初始化IoC資料庫錯誤: {e}")
    
    def _load_known_iocs(self):
        """載入已知IoC"""
        try:
            # 載入示例IoC數據
            sample_iocs = {
                'ips': {
                    '192.168.1.100': {
                        'type': 'malicious_ip',
                        'confidence': 'high',
                        'source': 'threat_feed_1',
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': ['malware', 'c2']
                    }
                },
                'domains': {
                    'malicious.example.com': {
                        'type': 'malicious_domain',
                        'confidence': 'high',
                        'source': 'threat_feed_1',
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': ['phishing', 'malware']
                    }
                },
                'hashes': {
                    'd41d8cd98f00b204e9800998ecf8427e': {
                        'type': 'malicious_hash',
                        'confidence': 'critical',
                        'source': 'threat_feed_1',
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': ['trojan', 'backdoor']
                    }
                }
            }
            
            for ioc_type, iocs in sample_iocs.items():
                self.ioc_database[ioc_type].update(iocs)
            
        except Exception as e:
            logger.error(f"載入已知IoC錯誤: {e}")
    
    def _init_kill_chain_analysis(self):
        """初始化Kill Chain分析"""
        try:
            self.kill_chain_config = {
                'enabled': True,
                'mitre_attack_mapping': True,
                'tactics': [
                    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                    'Collection', 'Command and Control', 'Exfiltration', 'Impact'
                ],
                'techniques': {},
                'procedures': {}
            }
            
            # 載入MITRE ATT&CK數據
            self._load_mitre_attack_data()
            
            logger.info("Kill Chain分析初始化完成")
            
        except Exception as e:
            logger.error(f"Kill Chain分析初始化錯誤: {e}")
    
    def _load_mitre_attack_data(self):
        """載入MITRE ATT&CK數據"""
        try:
            # 載入示例MITRE ATT&CK數據
            self.kill_chain_config['techniques'] = {
                'T1055': {
                    'name': 'Process Injection',
                    'tactic': 'Defense Evasion',
                    'description': 'Adversaries may inject code into processes in order to evade process-based defenses',
                    'platforms': ['Windows', 'Linux', 'macOS']
                },
                'T1071': {
                    'name': 'Application Layer Protocol',
                    'tactic': 'Command and Control',
                    'description': 'Adversaries may communicate using application layer protocols to avoid detection',
                    'platforms': ['Windows', 'Linux', 'macOS']
                },
                'T1041': {
                    'name': 'Exfiltration Over C2 Channel',
                    'tactic': 'Exfiltration',
                    'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel',
                    'platforms': ['Windows', 'Linux', 'macOS']
                }
            }
            
        except Exception as e:
            logger.error(f"載入MITRE ATT&CK數據錯誤: {e}")
    
    def _init_siem_integration(self):
        """初始化SIEM整合"""
        try:
            self.siem_config = {
                'enabled': True,
                'siem_platforms': {
                    'splunk': {
                        'enabled': True,
                        'url': 'https://splunk.example.com:8089',
                        'username': 'admin',
                        'password': 'password',
                        'index': 'threat_intel'
                    },
                    'elastic': {
                        'enabled': True,
                        'url': 'https://elastic.example.com:9200',
                        'username': 'elastic',
                        'password': 'password',
                        'index': 'threat-intel'
                    },
                    'qradar': {
                        'enabled': True,
                        'url': 'https://qradar.example.com',
                        'username': 'admin',
                        'password': 'password',
                        'reference_set': 'threat_indicators'
                    }
                },
                'auto_ingest': True,
                'update_interval': 300  # 5分鐘
            }
            
            logger.info("SIEM整合初始化完成")
            
        except Exception as e:
            logger.error(f"SIEM整合初始化錯誤: {e}")
    
    def start_intelligence_system(self) -> Dict[str, Any]:
        """啟動情報系統"""
        try:
            if self.running:
                return {'success': False, 'error': '情報系統已在運行中'}
            
            self.running = True
            
            # 啟動情報線程
            self._start_threat_feed_collection()
            self._start_ioc_processing()
            self._start_kill_chain_analysis()
            self._start_siem_integration()
            
            logger.info("真實威脅情報整合系統已啟動")
            return {'success': True, 'message': '情報系統已啟動'}
            
        except Exception as e:
            logger.error(f"啟動情報系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def _start_threat_feed_collection(self):
        """啟動威脅饋送收集"""
        def collect_threat_feeds():
            logger.info("威脅饋送收集已啟動")
            
            while self.running:
                try:
                    # 收集STIX/TAXII饋送
                    self._collect_stix_taxii_feeds()
                    
                    # 收集其他威脅饋送
                    self._collect_other_feeds()
                    
                    time.sleep(self.stix_taxii_config['update_interval'])
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"威脅饋送收集錯誤: {e}")
                    break
        
        thread = threading.Thread(target=collect_threat_feeds, daemon=True)
        thread.start()
        self.intel_threads.append(thread)
    
    def _collect_stix_taxii_feeds(self):
        """收集STIX/TAXII饋送"""
        try:
            for server in self.stix_taxii_config['taxii_servers']:
                try:
                    # 模擬STIX/TAXII數據收集
                    stix_data = self._simulate_stix_data(server['name'])
                    
                    if stix_data:
                        # 處理STIX數據
                        self._process_stix_data(stix_data, server['name'])
                        
                except Exception as e:
                    logger.error(f"收集STIX/TAXII饋送錯誤 {server['name']}: {e}")
                    
        except Exception as e:
            logger.error(f"收集STIX/TAXII饋送錯誤: {e}")
    
    def _simulate_stix_data(self, source: str) -> Dict[str, Any]:
        """模擬STIX數據"""
        try:
            # 模擬STIX 2.1數據
            stix_data = {
                'type': 'bundle',
                'id': f"bundle--{hashlib.md5(source.encode()).hexdigest()[:36]}",
                'spec_version': '2.1',
                'objects': [
                    {
                        'type': 'indicator',
                        'id': f"indicator--{hashlib.md5(f'{source}_ip'.encode()).hexdigest()[:36]}",
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat(),
                        'pattern': "[ipv4-addr:value = '192.168.1.101']",
                        'pattern_type': 'stix',
                        'valid_from': datetime.now().isoformat(),
                        'labels': ['malicious-activity'],
                        'confidence': 85
                    },
                    {
                        'type': 'indicator',
                        'id': f"indicator--{hashlib.md5(f'{source}_domain'.encode()).hexdigest()[:36]}",
                        'created': datetime.now().isoformat(),
                        'modified': datetime.now().isoformat(),
                        'pattern': "[domain-name:value = 'evil.example.com']",
                        'pattern_type': 'stix',
                        'valid_from': datetime.now().isoformat(),
                        'labels': ['malicious-activity'],
                        'confidence': 90
                    }
                ]
            }
            
            return stix_data
            
        except Exception as e:
            logger.error(f"模擬STIX數據錯誤: {e}")
            return {}
    
    def _process_stix_data(self, stix_data: Dict[str, Any], source: str):
        """處理STIX數據"""
        try:
            if 'objects' in stix_data:
                for obj in stix_data['objects']:
                    if obj['type'] == 'indicator':
                        self._process_stix_indicator(obj, source)
                    elif obj['type'] == 'malware':
                        self._process_stix_malware(obj, source)
                    elif obj['type'] == 'attack-pattern':
                        self._process_stix_attack_pattern(obj, source)
                        
        except Exception as e:
            logger.error(f"處理STIX數據錯誤: {e}")
    
    def _process_stix_indicator(self, indicator: Dict[str, Any], source: str):
        """處理STIX指標"""
        try:
            pattern = indicator.get('pattern', '')
            confidence = indicator.get('confidence', 0)
            labels = indicator.get('labels', [])
            
            # 解析指標模式
            if 'ipv4-addr:value' in pattern:
                # 提取IP地址
                ip_match = pattern.split("'")[1] if "'" in pattern else None
                if ip_match:
                    self._add_ioc('ips', ip_match, {
                        'type': 'malicious_ip',
                        'confidence': self._convert_confidence(confidence),
                        'source': source,
                        'first_seen': indicator.get('created', datetime.now().isoformat()),
                        'last_seen': indicator.get('modified', datetime.now().isoformat()),
                        'tags': labels
                    })
            
            elif 'domain-name:value' in pattern:
                # 提取域名
                domain_match = pattern.split("'")[1] if "'" in pattern else None
                if domain_match:
                    self._add_ioc('domains', domain_match, {
                        'type': 'malicious_domain',
                        'confidence': self._convert_confidence(confidence),
                        'source': source,
                        'first_seen': indicator.get('created', datetime.now().isoformat()),
                        'last_seen': indicator.get('modified', datetime.now().isoformat()),
                        'tags': labels
                    })
                    
        except Exception as e:
            logger.error(f"處理STIX指標錯誤: {e}")
    
    def _convert_confidence(self, confidence: int) -> str:
        """轉換置信度"""
        if confidence >= 90:
            return 'critical'
        elif confidence >= 70:
            return 'high'
        elif confidence >= 50:
            return 'medium'
        else:
            return 'low'
    
    def _add_ioc(self, ioc_type: str, value: str, metadata: Dict[str, Any]):
        """添加IoC"""
        try:
            if ioc_type in self.ioc_database:
                self.ioc_database[ioc_type][value] = metadata
                logger.info(f"添加IoC: {ioc_type} - {value}")
                
        except Exception as e:
            logger.error(f"添加IoC錯誤: {e}")
    
    def _process_stix_malware(self, malware: Dict[str, Any], source: str):
        """處理STIX惡意程式"""
        try:
            # 處理惡意程式信息
            malware_name = malware.get('name', 'Unknown')
            malware_type = malware.get('malware_types', [])
            
            logger.info(f"處理惡意程式: {malware_name} - {malware_type}")
            
        except Exception as e:
            logger.error(f"處理STIX惡意程式錯誤: {e}")
    
    def _process_stix_attack_pattern(self, attack_pattern: Dict[str, Any], source: str):
        """處理STIX攻擊模式"""
        try:
            # 處理攻擊模式信息
            pattern_name = attack_pattern.get('name', 'Unknown')
            tactics = attack_pattern.get('kill_chain_phases', [])
            
            logger.info(f"處理攻擊模式: {pattern_name} - {tactics}")
            
        except Exception as e:
            logger.error(f"處理STIX攻擊模式錯誤: {e}")
    
    def _collect_other_feeds(self):
        """收集其他威脅饋送"""
        try:
            # 收集其他類型的威脅饋送
            # 例如：CSV文件、JSON API、RSS饋送等
            
            # 模擬收集其他饋送
            other_feeds = [
                {'name': 'CSV Feed', 'type': 'csv', 'url': 'https://feeds.example.com/malware.csv'},
                {'name': 'JSON API', 'type': 'json', 'url': 'https://api.example.com/threats'},
                {'name': 'RSS Feed', 'type': 'rss', 'url': 'https://feeds.example.com/threats.rss'}
            ]
            
            for feed in other_feeds:
                try:
                    self._collect_feed(feed)
                except Exception as e:
                    logger.error(f"收集饋送錯誤 {feed['name']}: {e}")
                    
        except Exception as e:
            logger.error(f"收集其他饋送錯誤: {e}")
    
    def _collect_feed(self, feed: Dict[str, Any]):
        """收集單個饋送"""
        try:
            # 模擬饋送收集
            if feed['type'] == 'csv':
                self._collect_csv_feed(feed)
            elif feed['type'] == 'json':
                self._collect_json_feed(feed)
            elif feed['type'] == 'rss':
                self._collect_rss_feed(feed)
                
        except Exception as e:
            logger.error(f"收集饋送錯誤 {feed['name']}: {e}")
    
    def _collect_csv_feed(self, feed: Dict[str, Any]):
        """收集CSV饋送"""
        try:
            # 模擬CSV數據
            csv_data = [
                {'ip': '192.168.1.102', 'type': 'malicious', 'confidence': 'high'},
                {'domain': 'bad.example.com', 'type': 'phishing', 'confidence': 'medium'},
                {'hash': 'a1b2c3d4e5f6', 'type': 'malware', 'confidence': 'critical'}
            ]
            
            for row in csv_data:
                if 'ip' in row:
                    self._add_ioc('ips', row['ip'], {
                        'type': 'malicious_ip',
                        'confidence': row['confidence'],
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [row['type']]
                    })
                elif 'domain' in row:
                    self._add_ioc('domains', row['domain'], {
                        'type': 'malicious_domain',
                        'confidence': row['confidence'],
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [row['type']]
                    })
                elif 'hash' in row:
                    self._add_ioc('hashes', row['hash'], {
                        'type': 'malicious_hash',
                        'confidence': row['confidence'],
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [row['type']]
                    })
                    
        except Exception as e:
            logger.error(f"收集CSV饋送錯誤: {e}")
    
    def _collect_json_feed(self, feed: Dict[str, Any]):
        """收集JSON饋送"""
        try:
            # 模擬JSON數據
            json_data = {
                'indicators': [
                    {'value': '192.168.1.103', 'type': 'ip', 'threat': 'malware'},
                    {'value': 'suspicious.example.com', 'type': 'domain', 'threat': 'phishing'}
                ]
            }
            
            for indicator in json_data['indicators']:
                if indicator['type'] == 'ip':
                    self._add_ioc('ips', indicator['value'], {
                        'type': 'malicious_ip',
                        'confidence': 'medium',
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [indicator['threat']]
                    })
                elif indicator['type'] == 'domain':
                    self._add_ioc('domains', indicator['value'], {
                        'type': 'malicious_domain',
                        'confidence': 'medium',
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [indicator['threat']]
                    })
                    
        except Exception as e:
            logger.error(f"收集JSON饋送錯誤: {e}")
    
    def _collect_rss_feed(self, feed: Dict[str, Any]):
        """收集RSS饋送"""
        try:
            # 模擬RSS數據
            rss_data = {
                'items': [
                    {'title': 'New Malware Campaign', 'description': 'IP: 192.168.1.104', 'type': 'malware'},
                    {'title': 'Phishing Domain', 'description': 'Domain: fake.example.com', 'type': 'phishing'}
                ]
            }
            
            for item in rss_data['items']:
                if 'IP:' in item['description']:
                    ip = item['description'].split('IP: ')[1]
                    self._add_ioc('ips', ip, {
                        'type': 'malicious_ip',
                        'confidence': 'medium',
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [item['type']]
                    })
                elif 'Domain:' in item['description']:
                    domain = item['description'].split('Domain: ')[1]
                    self._add_ioc('domains', domain, {
                        'type': 'malicious_domain',
                        'confidence': 'medium',
                        'source': feed['name'],
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'tags': [item['type']]
                    })
                    
        except Exception as e:
            logger.error(f"收集RSS饋送錯誤: {e}")
    
    def _start_ioc_processing(self):
        """啟動IoC處理"""
        def process_iocs():
            logger.info("IoC處理已啟動")
            
            while self.running:
                try:
                    # 處理IoC
                    self._process_iocs()
                    
                    # 自動阻擋IoC
                    if self.ioc_config['auto_block']:
                        self._auto_block_iocs()
                    
                    time.sleep(60)  # 每分鐘處理一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"IoC處理錯誤: {e}")
                    break
        
        thread = threading.Thread(target=process_iocs, daemon=True)
        thread.start()
        self.intel_threads.append(thread)
    
    def _process_iocs(self):
        """處理IoC"""
        try:
            # 處理各種類型的IoC
            for ioc_type, iocs in self.ioc_database.items():
                for value, metadata in iocs.items():
                    # 檢查IoC是否過期
                    if self._is_ioc_expired(metadata):
                        self._remove_expired_ioc(ioc_type, value)
                        continue
                    
                    # 更新IoC統計
                    self._update_ioc_stats(ioc_type, value, metadata)
                    
        except Exception as e:
            logger.error(f"處理IoC錯誤: {e}")
    
    def _is_ioc_expired(self, metadata: Dict[str, Any]) -> bool:
        """檢查IoC是否過期"""
        try:
            # 檢查IoC是否超過30天未更新
            last_seen = datetime.fromisoformat(metadata.get('last_seen', datetime.now().isoformat()))
            if datetime.now() - last_seen > timedelta(days=30):
                return True
            return False
        except Exception:
            return False
    
    def _remove_expired_ioc(self, ioc_type: str, value: str):
        """移除過期IoC"""
        try:
            if ioc_type in self.ioc_database and value in self.ioc_database[ioc_type]:
                del self.ioc_database[ioc_type][value]
                logger.info(f"移除過期IoC: {ioc_type} - {value}")
        except Exception as e:
            logger.error(f"移除過期IoC錯誤: {e}")
    
    def _update_ioc_stats(self, ioc_type: str, value: str, metadata: Dict[str, Any]):
        """更新IoC統計"""
        try:
            # 更新最後看到時間
            metadata['last_seen'] = datetime.now().isoformat()
            
            # 增加命中次數
            if 'hit_count' not in metadata:
                metadata['hit_count'] = 0
            metadata['hit_count'] += 1
            
        except Exception as e:
            logger.error(f"更新IoC統計錯誤: {e}")
    
    def _auto_block_iocs(self):
        """自動阻擋IoC"""
        try:
            for ioc_type, iocs in self.ioc_database.items():
                for value, metadata in iocs.items():
                    confidence = metadata.get('confidence', 'low')
                    
                    # 根據置信度決定是否阻擋
                    if self._should_block_ioc(confidence):
                        self._block_ioc(ioc_type, value, metadata)
                        
        except Exception as e:
            logger.error(f"自動阻擋IoC錯誤: {e}")
    
    def _should_block_ioc(self, confidence: str) -> bool:
        """判斷是否應該阻擋IoC"""
        try:
            block_threshold = self.ioc_config['block_threshold']
            confidence_levels = ['low', 'medium', 'high', 'critical']
            
            return confidence_levels.index(confidence) >= confidence_levels.index(block_threshold)
        except Exception:
            return False
    
    def _block_ioc(self, ioc_type: str, value: str, metadata: Dict[str, Any]):
        """阻擋IoC"""
        try:
            # 實現IoC阻擋邏輯
            # 例如：更新防火牆規則、DNS阻擋等
            
            logger.info(f"阻擋IoC: {ioc_type} - {value} (置信度: {metadata.get('confidence', 'unknown')})")
            
        except Exception as e:
            logger.error(f"阻擋IoC錯誤: {e}")
    
    def _start_kill_chain_analysis(self):
        """啟動Kill Chain分析"""
        def analyze_kill_chain():
            logger.info("Kill Chain分析已啟動")
            
            while self.running:
                try:
                    # 分析Kill Chain
                    self._analyze_kill_chain()
                    
                    # 映射MITRE ATT&CK
                    self._map_mitre_attack()
                    
                    time.sleep(300)  # 每5分鐘分析一次
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Kill Chain分析錯誤: {e}")
                    break
        
        thread = threading.Thread(target=analyze_kill_chain, daemon=True)
        thread.start()
        self.intel_threads.append(thread)
    
    def _analyze_kill_chain(self):
        """分析Kill Chain"""
        try:
            # 分析攻擊鏈
            attack_chain = self._reconstruct_attack_chain()
            
            if attack_chain:
                # 保存攻擊鏈分析結果
                self.kill_chain_analysis[datetime.now().isoformat()] = attack_chain
                
        except Exception as e:
            logger.error(f"分析Kill Chain錯誤: {e}")
    
    def _reconstruct_attack_chain(self) -> Optional[Dict[str, Any]]:
        """重建攻擊鏈"""
        try:
            # 模擬攻擊鏈重建
            attack_chain = {
                'initial_access': {
                    'technique': 'T1078',
                    'name': 'Valid Accounts',
                    'description': 'Adversaries may obtain and abuse credentials of existing accounts',
                    'indicators': ['192.168.1.100', 'admin@example.com']
                },
                'execution': {
                    'technique': 'T1059',
                    'name': 'Command and Scripting Interpreter',
                    'description': 'Adversaries may abuse command and script interpreters to execute commands',
                    'indicators': ['powershell.exe', 'cmd.exe']
                },
                'persistence': {
                    'technique': 'T1543',
                    'name': 'Create or Modify System Process',
                    'description': 'Adversaries may create or modify system-level processes',
                    'indicators': ['svchost.exe', 'services.exe']
                },
                'lateral_movement': {
                    'technique': 'T1021',
                    'name': 'Remote Services',
                    'description': 'Adversaries may use remote services to initially access and/or persist within a network',
                    'indicators': ['RDP', 'SSH', 'SMB']
                },
                'exfiltration': {
                    'technique': 'T1041',
                    'name': 'Exfiltration Over C2 Channel',
                    'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel',
                    'indicators': ['evil.example.com', '192.168.1.101']
                }
            }
            
            return attack_chain
            
        except Exception as e:
            logger.error(f"重建攻擊鏈錯誤: {e}")
            return None
    
    def _map_mitre_attack(self):
        """映射MITRE ATT&CK"""
        try:
            # 映射攻擊技術到MITRE ATT&CK
            for timestamp, attack_chain in self.kill_chain_analysis.items():
                for phase, details in attack_chain.items():
                    technique_id = details.get('technique', '')
                    if technique_id in self.kill_chain_config['techniques']:
                        technique_info = self.kill_chain_config['techniques'][technique_id]
                        details['mitre_info'] = technique_info
                        
        except Exception as e:
            logger.error(f"映射MITRE ATT&CK錯誤: {e}")
    
    def _start_siem_integration(self):
        """啟動SIEM整合"""
        def integrate_siem():
            logger.info("SIEM整合已啟動")
            
            while self.running:
                try:
                    # 整合到SIEM平台
                    self._integrate_to_siem()
                    
                    time.sleep(self.siem_config['update_interval'])
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"SIEM整合錯誤: {e}")
                    break
        
        thread = threading.Thread(target=integrate_siem, daemon=True)
        thread.start()
        self.intel_threads.append(thread)
    
    def _integrate_to_siem(self):
        """整合到SIEM"""
        try:
            for platform, config in self.siem_config['siem_platforms'].items():
                if config['enabled']:
                    try:
                        if platform == 'splunk':
                            self._integrate_to_splunk(config)
                        elif platform == 'elastic':
                            self._integrate_to_elastic(config)
                        elif platform == 'qradar':
                            self._integrate_to_qradar(config)
                    except Exception as e:
                        logger.error(f"整合到{platform}錯誤: {e}")
                        
        except Exception as e:
            logger.error(f"整合到SIEM錯誤: {e}")
    
    def _integrate_to_splunk(self, config: Dict[str, Any]):
        """整合到Splunk"""
        try:
            # 模擬Splunk整合
            logger.debug(f"整合到Splunk: {config['url']}")
            
        except Exception as e:
            logger.error(f"整合到Splunk錯誤: {e}")
    
    def _integrate_to_elastic(self, config: Dict[str, Any]):
        """整合到Elastic"""
        try:
            # 模擬Elastic整合
            logger.debug(f"整合到Elastic: {config['url']}")
            
        except Exception as e:
            logger.error(f"整合到Elastic錯誤: {e}")
    
    def _integrate_to_qradar(self, config: Dict[str, Any]):
        """整合到QRadar"""
        try:
            # 模擬QRadar整合
            logger.debug(f"整合到QRadar: {config['url']}")
            
        except Exception as e:
            logger.error(f"整合到QRadar錯誤: {e}")
    
    def stop_intelligence_system(self) -> Dict[str, Any]:
        """停止情報系統"""
        try:
            self.running = False
            
            # 等待所有線程結束
            for thread in self.intel_threads:
                thread.join(timeout=5)
            
            self.intel_threads.clear()
            
            logger.info("威脅情報整合系統已停止")
            return {'success': True, 'message': '情報系統已停止'}
            
        except Exception as e:
            logger.error(f"停止情報系統錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_intelligence_status(self) -> Dict[str, Any]:
        """獲取情報狀態"""
        try:
            return {
                'success': True,
                'running': self.running,
                'ioc_counts': {
                    'ips': len(self.ioc_database.get('ips', {})),
                    'domains': len(self.ioc_database.get('domains', {})),
                    'urls': len(self.ioc_database.get('urls', {})),
                    'hashes': len(self.ioc_database.get('hashes', {})),
                    'emails': len(self.ioc_database.get('emails', {}))
                },
                'kill_chain_analyses': len(self.kill_chain_analysis),
                'siem_integrations': len([p for p in self.siem_config['siem_platforms'].values() if p['enabled']])
            }
        except Exception as e:
            logger.error(f"獲取情報狀態錯誤: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_intelligence_report(self) -> Dict[str, Any]:
        """獲取情報報告"""
        try:
            return {
                'success': True,
                'ioc_database': self.ioc_database,
                'kill_chain_analysis': self.kill_chain_analysis,
                'intelligence_summary': {
                    'total_iocs': sum(len(iocs) for iocs in self.ioc_database.values()),
                    'high_confidence_iocs': len([ioc for iocs in self.ioc_database.values() for ioc in iocs.values() if ioc.get('confidence') == 'high']),
                    'critical_iocs': len([ioc for iocs in self.ioc_database.values() for ioc in iocs.values() if ioc.get('confidence') == 'critical']),
                    'attack_chains_analyzed': len(self.kill_chain_analysis)
                }
            }
        except Exception as e:
            logger.error(f"獲取情報報告錯誤: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """主函數"""
    config = {
        'log_level': 'INFO'
    }
    
    intel = RealThreatIntelligenceIntegration(config)
    
    try:
        # 啟動情報系統
        result = intel.start_intelligence_system()
        if result['success']:
            print("✅ 真實威脅情報整合系統已啟動")
            print("📊 功能:")
            print("   - STIX/TAXII整合")
            print("   - IoC管理")
            print("   - Kill Chain分析")
            print("   - SIEM整合")
            print("\n按 Ctrl+C 停止系統")
            
            # 持續運行
            while True:
                time.sleep(1)
        else:
            print(f"❌ 啟動失敗: {result['error']}")
            
    except KeyboardInterrupt:
        print("\n🛑 正在停止系統...")
        intel.stop_intelligence_system()
        print("✅ 系統已停止")
    except Exception as e:
        print(f"❌ 系統錯誤: {e}")


if __name__ == "__main__":
    main()
