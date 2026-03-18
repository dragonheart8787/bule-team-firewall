#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威脅情報管理系統
Threat Intelligence Management System

功能特色：
- 多源威脅情報整合
- 即時威脅情報更新
- 威脅情報分析
- 自動化威脅響應
- 威脅情報共享
- 軍事級威脅評估
"""

import json
import time
import hashlib
import logging
import requests
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import ipaddress
import re
import yaml
from urllib.parse import urlparse
import feedparser
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import os

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """威脅類型"""
    MALWARE = "MALWARE"
    BOTNET = "BOTNET"
    PHISHING = "PHISHING"
    SPAM = "SPAM"
    DDOS = "DDOS"
    APT = "APT"
    RANSOMWARE = "RANSOMWARE"
    TROJAN = "TROJAN"
    VIRUS = "VIRUS"
    WORM = "WORM"
    SPYWARE = "SPYWARE"
    ADWARE = "ADWARE"
    ROOTKIT = "ROOTKIT"
    BACKDOOR = "BACKDOOR"
    KEYLOGGER = "KEYLOGGER"
    UNKNOWN = "UNKNOWN"

class ConfidenceLevel(Enum):
    """可信度等級"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4
    CONFIRMED = 5

class ThreatSource(Enum):
    """威脅來源"""
    COMMERCIAL = "COMMERCIAL"
    GOVERNMENT = "GOVERNMENT"
    ACADEMIC = "ACADEMIC"
    COMMUNITY = "COMMUNITY"
    INTERNAL = "INTERNAL"
    MILITARY = "MILITARY"

@dataclass
class ThreatIndicator:
    """威脅指標"""
    id: str
    value: str
    type: str  # IP, Domain, URL, Hash, Email
    threat_type: ThreatType
    confidence: ConfidenceLevel
    source: ThreatSource
    first_seen: datetime
    last_seen: datetime
    description: str
    tags: List[str]
    false_positive: bool = False
    military_classification: str = "UNCLASSIFIED"

@dataclass
class ThreatFeed:
    """威脅情報源"""
    id: str
    name: str
    url: str
    type: str  # RSS, JSON, CSV, XML
    enabled: bool
    update_interval: int  # 秒
    last_update: datetime
    reliability_score: float
    source_type: ThreatSource
    authentication: Dict[str, str] = None

@dataclass
class ThreatReport:
    """威脅報告"""
    id: str
    title: str
    description: str
    threat_type: ThreatType
    severity: str
    indicators: List[ThreatIndicator]
    source: str
    published_date: datetime
    military_relevance: bool
    classification: str

class ThreatIntelligenceManager:
    """威脅情報管理器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.feeds: List[ThreatFeed] = []
        self.reports: List[ThreatReport] = []
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.update_queue = queue.Queue()
        self.running = False
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設威脅情報源
        self._load_default_feeds()
        
        # 載入本地威脅情報
        self._load_local_intelligence()
        
        logger.info("威脅情報管理系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('threat_intel.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立威脅指標表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                threat_type TEXT,
                confidence INTEGER,
                source TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                description TEXT,
                tags TEXT,
                false_positive BOOLEAN,
                military_classification TEXT
            )
        ''')
        
        # 建立威脅情報源表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_feeds (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                type TEXT,
                enabled BOOLEAN,
                update_interval INTEGER,
                last_update TIMESTAMP,
                reliability_score REAL,
                source_type TEXT,
                authentication TEXT
            )
        ''')
        
        # 建立威脅報告表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_reports (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                threat_type TEXT,
                severity TEXT,
                indicators TEXT,
                source TEXT,
                published_date TIMESTAMP,
                military_relevance BOOLEAN,
                classification TEXT
            )
        ''')
        
        # 建立黑名單表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                value TEXT PRIMARY KEY,
                threat_type TEXT,
                added_date TIMESTAMP,
                source TEXT,
                confidence REAL
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_feeds(self):
        """載入預設威脅情報源"""
        default_feeds = [
            ThreatFeed(
                id="feed_001",
                name="Malware Domain List",
                url="https://feeds.malware-domains.com/domain_list.txt",
                type="TXT",
                enabled=True,
                update_interval=3600,
                last_update=datetime.now(),
                reliability_score=0.8,
                source_type=ThreatSource.COMMUNITY
            ),
            ThreatFeed(
                id="feed_002",
                name="Emerging Threats",
                url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                type="TXT",
                enabled=True,
                update_interval=1800,
                last_update=datetime.now(),
                reliability_score=0.9,
                source_type=ThreatSource.COMMERCIAL
            ),
            ThreatFeed(
                id="feed_003",
                name="AlienVault Reputation",
                url="https://reputation.alienvault.com/reputation.data",
                type="TXT",
                enabled=True,
                update_interval=7200,
                last_update=datetime.now(),
                reliability_score=0.85,
                source_type=ThreatSource.COMMERCIAL
            ),
            ThreatFeed(
                id="feed_004",
                name="Malware Domain List IP",
                url="https://www.malwaredomainlist.com/hostslist/ip.txt",
                type="TXT",
                enabled=True,
                update_interval=3600,
                last_update=datetime.now(),
                reliability_score=0.75,
                source_type=ThreatSource.COMMUNITY
            ),
            ThreatFeed(
                id="feed_005",
                name="Cisco Talos Intelligence",
                url="https://talosintelligence.com/documents/ip-blacklist",
                type="TXT",
                enabled=True,
                update_interval=14400,
                last_update=datetime.now(),
                reliability_score=0.95,
                source_type=ThreatSource.COMMERCIAL
            )
        ]
        
        for feed in default_feeds:
            self.add_feed(feed)

    def _load_local_intelligence(self):
        """載入本地威脅情報"""
        # 從資料庫載入現有指標
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM threat_indicators')
        rows = cursor.fetchall()
        
        for row in rows:
            indicator = ThreatIndicator(
                id=row[0],
                value=row[1],
                type=row[2],
                threat_type=ThreatType(row[3]) if row[3] else ThreatType.UNKNOWN,
                confidence=ConfidenceLevel(row[4]) if row[4] else ConfidenceLevel.MEDIUM,
                source=ThreatSource(row[5]) if row[5] else ThreatSource.COMMUNITY,
                first_seen=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                last_seen=datetime.fromisoformat(row[7]) if row[7] else datetime.now(),
                description=row[8] or "",
                tags=json.loads(row[9]) if row[9] else [],
                false_positive=bool(row[10]),
                military_classification=row[11] or "UNCLASSIFIED"
            )
            self.indicators[indicator.id] = indicator
            
            # 加入黑名單
            if not indicator.false_positive:
                self.blacklist.add(indicator.value)
        
        # 載入黑名單
        cursor.execute('SELECT * FROM blacklist')
        rows = cursor.fetchall()
        
        for row in rows:
            self.blacklist.add(row[0])

    def add_feed(self, feed: ThreatFeed):
        """新增威脅情報源"""
        self.feeds.append(feed)
        
        # 儲存到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_feeds 
            (id, name, url, type, enabled, update_interval, last_update, 
             reliability_score, source_type, authentication)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            feed.id, feed.name, feed.url, feed.type, feed.enabled,
            feed.update_interval, feed.last_update.isoformat(),
            feed.reliability_score, feed.source_type.value,
            json.dumps(feed.authentication) if feed.authentication else None
        ))
        self.db_conn.commit()
        
        logger.info(f"已新增威脅情報源: {feed.name}")

    def start_monitoring(self):
        """開始監控威脅情報"""
        self.running = True
        
        # 啟動更新線程
        update_thread = threading.Thread(target=self._update_loop, daemon=True)
        update_thread.start()
        
        # 啟動處理線程
        process_thread = threading.Thread(target=self._process_loop, daemon=True)
        process_thread.start()
        
        logger.info("威脅情報監控已啟動")

    def stop_monitoring(self):
        """停止監控"""
        self.running = False
        self.db_conn.close()
        logger.info("威脅情報監控已停止")

    def _update_loop(self):
        """更新循環"""
        while self.running:
            try:
                for feed in self.feeds:
                    if not feed.enabled:
                        continue
                    
                    # 檢查是否需要更新
                    time_since_update = (datetime.now() - feed.last_update).total_seconds()
                    if time_since_update >= feed.update_interval:
                        self.update_queue.put(feed)
                
                time.sleep(60)  # 每分鐘檢查一次
            
            except Exception as e:
                logger.error(f"威脅情報更新循環錯誤: {e}")
                time.sleep(300)  # 錯誤時等待5分鐘

    def _process_loop(self):
        """處理循環"""
        while self.running:
            try:
                feed = self.update_queue.get(timeout=1)
                self._update_feed(feed)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"威脅情報處理錯誤: {e}")

    def _update_feed(self, feed: ThreatFeed):
        """更新威脅情報源"""
        try:
            logger.info(f"更新威脅情報源: {feed.name}")
            
            # 下載威脅情報
            data = self._download_feed(feed)
            if not data:
                return
            
            # 解析威脅情報
            indicators = self._parse_feed_data(data, feed)
            
            # 處理新指標
            new_count = 0
            for indicator in indicators:
                if indicator.id not in self.indicators:
                    self._add_indicator(indicator)
                    new_count += 1
            
            # 更新最後更新時間
            feed.last_update = datetime.now()
            cursor = self.db_conn.cursor()
            cursor.execute('''
                UPDATE threat_feeds SET last_update = ? WHERE id = ?
            ''', (feed.last_update.isoformat(), feed.id))
            self.db_conn.commit()
            
            logger.info(f"威脅情報源 {feed.name} 更新完成，新增 {new_count} 個指標")
        
        except Exception as e:
            logger.error(f"更新威脅情報源 {feed.name} 失敗: {e}")

    def _download_feed(self, feed: ThreatFeed) -> Optional[str]:
        """下載威脅情報源"""
        try:
            headers = {
                'User-Agent': 'Military-Firewall-Threat-Intelligence/1.0'
            }
            
            # 添加認證
            if feed.authentication:
                if 'api_key' in feed.authentication:
                    headers['Authorization'] = f"Bearer {feed.authentication['api_key']}"
                elif 'username' in feed.authentication and 'password' in feed.authentication:
                    from requests.auth import HTTPBasicAuth
                    auth = HTTPBasicAuth(feed.authentication['username'], feed.authentication['password'])
                else:
                    auth = None
            else:
                auth = None
            
            response = requests.get(feed.url, headers=headers, auth=auth, timeout=30)
            response.raise_for_status()
            
            return response.text
        
        except Exception as e:
            logger.error(f"下載威脅情報源 {feed.name} 失敗: {e}")
            return None

    def _parse_feed_data(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析威脅情報資料"""
        indicators = []
        
        try:
            if feed.type == "TXT":
                indicators = self._parse_txt_feed(data, feed)
            elif feed.type == "JSON":
                indicators = self._parse_json_feed(data, feed)
            elif feed.type == "XML":
                indicators = self._parse_xml_feed(data, feed)
            elif feed.type == "CSV":
                indicators = self._parse_csv_feed(data, feed)
            elif feed.type == "RSS":
                indicators = self._parse_rss_feed(data, feed)
        
        except Exception as e:
            logger.error(f"解析威脅情報資料失敗: {e}")
        
        return indicators

    def _parse_txt_feed(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析TXT格式威脅情報"""
        indicators = []
        lines = data.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 解析行格式
            parts = line.split()
            if not parts:
                continue
            
            value = parts[0]
            threat_type = ThreatType.MALWARE  # 預設類型
            
            # 根據URL判斷威脅類型
            if 'malware' in feed.name.lower():
                threat_type = ThreatType.MALWARE
            elif 'botnet' in feed.name.lower():
                threat_type = ThreatType.BOTNET
            elif 'phishing' in feed.name.lower():
                threat_type = ThreatType.PHISHING
            elif 'spam' in feed.name.lower():
                threat_type = ThreatType.SPAM
            
            # 判斷指標類型
            indicator_type = self._detect_indicator_type(value)
            
            indicator = ThreatIndicator(
                id=self._generate_indicator_id(value, feed.id),
                value=value,
                type=indicator_type,
                threat_type=threat_type,
                confidence=ConfidenceLevel.MEDIUM,
                source=feed.source_type,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description=f"來自 {feed.name} 的威脅情報",
                tags=[feed.name.lower().replace(' ', '_')],
                military_classification="UNCLASSIFIED"
            )
            
            indicators.append(indicator)
        
        return indicators

    def _parse_json_feed(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析JSON格式威脅情報"""
        indicators = []
        
        try:
            json_data = json.loads(data)
            
            # 處理不同的JSON格式
            if isinstance(json_data, list):
                for item in json_data:
                    indicator = self._parse_json_item(item, feed)
                    if indicator:
                        indicators.append(indicator)
            elif isinstance(json_data, dict):
                if 'indicators' in json_data:
                    for item in json_data['indicators']:
                        indicator = self._parse_json_item(item, feed)
                        if indicator:
                            indicators.append(indicator)
                else:
                    indicator = self._parse_json_item(json_data, feed)
                    if indicator:
                        indicators.append(indicator)
        
        except Exception as e:
            logger.error(f"解析JSON威脅情報失敗: {e}")
        
        return indicators

    def _parse_json_item(self, item: Dict, feed: ThreatFeed) -> Optional[ThreatIndicator]:
        """解析JSON項目"""
        try:
            # 提取基本資訊
            value = item.get('value') or item.get('indicator') or item.get('ip') or item.get('domain')
            if not value:
                return None
            
            threat_type = ThreatType(item.get('threat_type', 'MALWARE'))
            confidence = ConfidenceLevel(item.get('confidence', 3))
            
            indicator = ThreatIndicator(
                id=self._generate_indicator_id(value, feed.id),
                value=str(value),
                type=self._detect_indicator_type(str(value)),
                threat_type=threat_type,
                confidence=confidence,
                source=feed.source_type,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description=item.get('description', f"來自 {feed.name} 的威脅情報"),
                tags=item.get('tags', [feed.name.lower().replace(' ', '_')]),
                military_classification=item.get('classification', 'UNCLASSIFIED')
            )
            
            return indicator
        
        except Exception as e:
            logger.error(f"解析JSON項目失敗: {e}")
            return None

    def _parse_xml_feed(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析XML格式威脅情報"""
        indicators = []
        
        try:
            root = ET.fromstring(data)
            
            # 處理STIX格式
            if root.tag.endswith('STIX_Package'):
                indicators = self._parse_stix_format(root, feed)
            else:
                # 處理一般XML格式
                indicators = self._parse_generic_xml(root, feed)
        
        except Exception as e:
            logger.error(f"解析XML威脅情報失敗: {e}")
        
        return indicators

    def _parse_stix_format(self, root, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析STIX格式"""
        indicators = []
        
        # 簡化的STIX解析
        for observable in root.findall('.//{http://stix.mitre.org/Indicator-2}Indicator'):
            title = observable.find('.//{http://stix.mitre.org/Indicator-2}Title')
            description = observable.find('.//{http://stix.mitre.org/Indicator-2}Description')
            
            if title is not None:
                value = title.text
                indicator = ThreatIndicator(
                    id=self._generate_indicator_id(value, feed.id),
                    value=value,
                    type=self._detect_indicator_type(value),
                    threat_type=ThreatType.MALWARE,
                    confidence=ConfidenceLevel.MEDIUM,
                    source=feed.source_type,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    description=description.text if description is not None else f"來自 {feed.name} 的STIX威脅情報",
                    tags=['stix', feed.name.lower().replace(' ', '_')],
                    military_classification="UNCLASSIFIED"
                )
                indicators.append(indicator)
        
        return indicators

    def _parse_generic_xml(self, root, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析一般XML格式"""
        indicators = []
        
        # 尋找包含IP、域名或URL的元素
        for elem in root.iter():
            text = elem.text
            if text and self._is_valid_indicator(text):
                indicator = ThreatIndicator(
                    id=self._generate_indicator_id(text, feed.id),
                    value=text,
                    type=self._detect_indicator_type(text),
                    threat_type=ThreatType.MALWARE,
                    confidence=ConfidenceLevel.MEDIUM,
                    source=feed.source_type,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    description=f"來自 {feed.name} 的XML威脅情報",
                    tags=['xml', feed.name.lower().replace(' ', '_')],
                    military_classification="UNCLASSIFIED"
                )
                indicators.append(indicator)
        
        return indicators

    def _parse_csv_feed(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析CSV格式威脅情報"""
        indicators = []
        lines = data.strip().split('\n')
        
        if not lines:
            return indicators
        
        # 解析標題行
        headers = lines[0].split(',')
        
        for line in lines[1:]:
            values = line.split(',')
            if len(values) < len(headers):
                continue
            
            # 建立字典
            row = dict(zip(headers, values))
            
            # 提取指標值
            value = None
            for key in ['value', 'indicator', 'ip', 'domain', 'url']:
                if key in row and row[key]:
                    value = row[key].strip()
                    break
            
            if not value:
                continue
            
            indicator = ThreatIndicator(
                id=self._generate_indicator_id(value, feed.id),
                value=value,
                type=self._detect_indicator_type(value),
                threat_type=ThreatType.MALWARE,
                confidence=ConfidenceLevel.MEDIUM,
                source=feed.source_type,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description=f"來自 {feed.name} 的CSV威脅情報",
                tags=['csv', feed.name.lower().replace(' ', '_')],
                military_classification="UNCLASSIFIED"
            )
            
            indicators.append(indicator)
        
        return indicators

    def _parse_rss_feed(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """解析RSS格式威脅情報"""
        indicators = []
        
        try:
            feed_data = feedparser.parse(data)
            
            for entry in feed_data.entries:
                # 從標題和描述中提取指標
                text = f"{entry.title} {entry.description}"
                
                # 使用正則表達式尋找IP地址、域名等
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
                
                ips = re.findall(ip_pattern, text)
                domains = re.findall(domain_pattern, text)
                
                for ip in ips:
                    if self._is_valid_ip(ip):
                        indicator = ThreatIndicator(
                            id=self._generate_indicator_id(ip, feed.id),
                            value=ip,
                            type="IP",
                            threat_type=ThreatType.MALWARE,
                            confidence=ConfidenceLevel.MEDIUM,
                            source=feed.source_type,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            description=f"來自 {feed.name} RSS: {entry.title}",
                            tags=['rss', feed.name.lower().replace(' ', '_')],
                            military_classification="UNCLASSIFIED"
                        )
                        indicators.append(indicator)
                
                for domain in domains:
                    if self._is_valid_domain(domain):
                        indicator = ThreatIndicator(
                            id=self._generate_indicator_id(domain, feed.id),
                            value=domain,
                            type="Domain",
                            threat_type=ThreatType.MALWARE,
                            confidence=ConfidenceLevel.MEDIUM,
                            source=feed.source_type,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            description=f"來自 {feed.name} RSS: {entry.title}",
                            tags=['rss', feed.name.lower().replace(' ', '_')],
                            military_classification="UNCLASSIFIED"
                        )
                        indicators.append(indicator)
        
        except Exception as e:
            logger.error(f"解析RSS威脅情報失敗: {e}")
        
        return indicators

    def _detect_indicator_type(self, value: str) -> str:
        """檢測指標類型"""
        value = value.strip()
        
        # IP地址
        if self._is_valid_ip(value):
            return "IP"
        
        # 域名
        if self._is_valid_domain(value):
            return "Domain"
        
        # URL
        if value.startswith(('http://', 'https://')):
            return "URL"
        
        # Email
        if '@' in value and '.' in value:
            return "Email"
        
        # Hash
        if len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value):
            return "Hash"
        
        return "Unknown"

    def _is_valid_ip(self, ip: str) -> bool:
        """檢查是否為有效IP地址"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """檢查是否為有效域名"""
        try:
            # 簡單的域名驗證
            if len(domain) > 253:
                return False
            
            parts = domain.split('.')
            if len(parts) < 2:
                return False
            
            for part in parts:
                if not part or len(part) > 63:
                    return False
                if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', part):
                    return False
            
            return True
        except:
            return False

    def _is_valid_indicator(self, value: str) -> bool:
        """檢查是否為有效指標"""
        return (self._is_valid_ip(value) or 
                self._is_valid_domain(value) or
                value.startswith(('http://', 'https://')) or
                '@' in value or
                len(value) in [32, 40, 64])

    def _generate_indicator_id(self, value: str, feed_id: str) -> str:
        """生成指標ID"""
        hash_input = f"{value}_{feed_id}_{datetime.now().isoformat()}"
        return hashlib.md5(hash_input.encode()).hexdigest()

    def _add_indicator(self, indicator: ThreatIndicator):
        """新增威脅指標"""
        self.indicators[indicator.id] = indicator
        
        # 加入黑名單
        if not indicator.false_positive:
            self.blacklist.add(indicator.value)
        
        # 儲存到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO threat_indicators 
            (id, value, type, threat_type, confidence, source, first_seen, 
             last_seen, description, tags, false_positive, military_classification)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            indicator.id, indicator.value, indicator.type, indicator.threat_type.value,
            indicator.confidence.value, indicator.source.value, indicator.first_seen.isoformat(),
            indicator.last_seen.isoformat(), indicator.description, json.dumps(indicator.tags),
            indicator.false_positive, indicator.military_classification
        ))
        self.db_conn.commit()

    def check_threat(self, value: str) -> Optional[ThreatIndicator]:
        """檢查威脅"""
        # 直接查找
        for indicator in self.indicators.values():
            if indicator.value == value and not indicator.false_positive:
                return indicator
        
        return None

    def is_blacklisted(self, value: str) -> bool:
        """檢查是否在黑名單中"""
        return value in self.blacklist

    def is_whitelisted(self, value: str) -> bool:
        """檢查是否在白名單中"""
        return value in self.whitelist

    def add_to_blacklist(self, value: str, threat_type: ThreatType = ThreatType.MALWARE, 
                        source: str = "Manual", confidence: float = 1.0):
        """手動加入黑名單"""
        self.blacklist.add(value)
        
        # 儲存到資料庫
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO blacklist 
            (value, threat_type, added_date, source, confidence)
            VALUES (?, ?, ?, ?, ?)
        ''', (value, threat_type.value, datetime.now().isoformat(), source, confidence))
        self.db_conn.commit()
        
        logger.info(f"已將 {value} 加入黑名單")

    def remove_from_blacklist(self, value: str):
        """從黑名單移除"""
        self.blacklist.discard(value)
        
        # 從資料庫移除
        cursor = self.db_conn.cursor()
        cursor.execute('DELETE FROM blacklist WHERE value = ?', (value,))
        self.db_conn.commit()
        
        logger.info(f"已從黑名單移除 {value}")

    def get_statistics(self) -> Dict:
        """獲取統計資訊"""
        stats = {
            'total_indicators': len(self.indicators),
            'blacklist_size': len(self.blacklist),
            'whitelist_size': len(self.whitelist),
            'active_feeds': len([f for f in self.feeds if f.enabled]),
            'indicators_by_type': defaultdict(int),
            'indicators_by_threat_type': defaultdict(int),
            'indicators_by_source': defaultdict(int),
            'recent_updates': []
        }
        
        # 統計指標類型
        for indicator in self.indicators.values():
            stats['indicators_by_type'][indicator.type] += 1
            stats['indicators_by_threat_type'][indicator.threat_type.value] += 1
            stats['indicators_by_source'][indicator.source.value] += 1
        
        # 最近更新
        recent_indicators = sorted(
            self.indicators.values(), 
            key=lambda x: x.last_seen, 
            reverse=True
        )[:10]
        
        stats['recent_updates'] = [
            {
                'value': indicator.value,
                'type': indicator.type,
                'threat_type': indicator.threat_type.value,
                'last_seen': indicator.last_seen.isoformat(),
                'source': indicator.source.value
            }
            for indicator in recent_indicators
        ]
        
        return stats

    def export_blacklist(self, format: str = "txt") -> str:
        """匯出黑名單"""
        if format == "txt":
            return "\n".join(sorted(self.blacklist))
        elif format == "json":
            return json.dumps(list(self.blacklist), indent=2)
        elif format == "csv":
            return "value,threat_type,added_date\n" + "\n".join(
                f"{value},MALWARE,{datetime.now().isoformat()}" 
                for value in sorted(self.blacklist)
            )
        else:
            raise ValueError(f"不支援的格式: {format}")

    def import_blacklist(self, data: str, format: str = "txt"):
        """匯入黑名單"""
        if format == "txt":
            lines = data.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.add_to_blacklist(line)
        elif format == "json":
            blacklist_data = json.loads(data)
            for value in blacklist_data:
                self.add_to_blacklist(value)
        elif format == "csv":
            lines = data.strip().split('\n')[1:]  # 跳過標題行
            for line in lines:
                parts = line.split(',')
                if parts:
                    self.add_to_blacklist(parts[0])
        
        logger.info(f"已匯入黑名單，格式: {format}")

def main():
    """主程式"""
    config = {
        'threat_intel': {
            'enabled': True,
            'update_interval': 3600,
            'sources': []
        }
    }
    
    ti_manager = ThreatIntelligenceManager(config)
    
    try:
        ti_manager.start_monitoring()
        
        # 主循環
        while True:
            time.sleep(1)
            
            # 顯示統計資訊
            stats = ti_manager.get_statistics()
            if stats['total_indicators'] % 100 == 0:
                logger.info(f"威脅指標總數: {stats['total_indicators']}, "
                          f"黑名單大小: {stats['blacklist_size']}")
    
    except KeyboardInterrupt:
        logger.info("收到中斷信號")
    finally:
        ti_manager.stop_monitoring()

if __name__ == "__main__":
    main()

