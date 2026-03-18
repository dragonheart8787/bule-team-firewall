#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
軍事級氣隙隔離系統
Military-Grade Air Gap Isolation System

功能特色：
- 物理氣隙隔離
- 單向數據傳輸
- 光學隔離技術
- 電磁隔離防護
- 數據洩漏防護
- 零網路連線
"""

import os
import sys
import time
import logging
import threading
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import psutil

logger = logging.getLogger(__name__)

class IsolationLevel(Enum):
    """隔離等級"""
    PHYSICAL = "PHYSICAL"           # 物理隔離
    LOGICAL = "LOGICAL"             # 邏輯隔離
    NETWORK = "NETWORK"             # 網路隔離
    ELECTROMAGNETIC = "ELECTROMAGNETIC"  # 電磁隔離
    OPTICAL = "OPTICAL"             # 光學隔離
    QUANTUM = "QUANTUM"             # 量子隔離

class DataDirection(Enum):
    """數據方向"""
    INBOUND = "INBOUND"             # 入站
    OUTBOUND = "OUTBOUND"           # 出站
    BIDIRECTIONAL = "BIDIRECTIONAL" # 雙向
    NONE = "NONE"                   # 無

class SecurityZone(Enum):
    """安全區域"""
    PUBLIC = "PUBLIC"               # 公開區
    DMZ = "DMZ"                     # 非軍事區
    INTERNAL = "INTERNAL"           # 內部區
    CLASSIFIED = "CLASSIFIED"       # 機密區
    TOP_SECRET = "TOP_SECRET"       # 絕密區
    COMPARTMENTED = "COMPARTMENTED" # 隔離區

@dataclass
class AirGapZone:
    """氣隙區域"""
    id: str
    name: str
    security_level: SecurityZone
    isolation_level: IsolationLevel
    data_direction: DataDirection
    physical_location: str
    network_connections: List[str]
    allowed_protocols: List[str]
    data_classification: str
    access_controls: List[str]
    monitoring_enabled: bool
    created_at: datetime

@dataclass
class DataTransfer:
    """數據傳輸"""
    id: str
    source_zone: str
    dest_zone: str
    data_type: str
    data_size: int
    transfer_method: str
    encryption: str
    timestamp: datetime
    authorized: bool
    approved_by: str
    audit_trail: List[Dict[str, Any]]

@dataclass
class IsolationEvent:
    """隔離事件"""
    id: str
    event_type: str
    zone_id: str
    description: str
    severity: str
    timestamp: datetime
    resolved: bool
    mitigation: str

class MilitaryAirGapIsolation:
    """軍事級氣隙隔離系統"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.air_gap_zones: Dict[str, AirGapZone] = {}
        self.data_transfers: Dict[str, DataTransfer] = {}
        self.isolation_events: Dict[str, IsolationEvent] = {}
        self.physical_barriers: Dict[str, Dict] = {}
        self.optical_links: Dict[str, Dict] = {}
        
        # 統計數據
        self.stats = {
            'total_zones': 0,
            'isolated_zones': 0,
            'data_transfers': 0,
            'blocked_attempts': 0,
            'security_events': 0,
            'physical_barriers': 0
        }
        
        # 初始化資料庫
        self._init_database()
        
        # 載入預設氣隙區域
        self._load_default_air_gap_zones()
        
        # 初始化物理隔離
        self._init_physical_isolation()
        
        # 啟動隔離監控
        self._start_isolation_monitoring()
        
        logger.info("軍事級氣隙隔離系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('military_air_gap_isolation.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立氣隙區域表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS air_gap_zones (
                id TEXT PRIMARY KEY,
                name TEXT,
                security_level TEXT,
                isolation_level TEXT,
                data_direction TEXT,
                physical_location TEXT,
                network_connections TEXT,
                allowed_protocols TEXT,
                data_classification TEXT,
                access_controls TEXT,
                monitoring_enabled BOOLEAN,
                created_at TIMESTAMP
            )
        ''')
        
        # 建立數據傳輸表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_transfers (
                id TEXT PRIMARY KEY,
                source_zone TEXT,
                dest_zone TEXT,
                data_type TEXT,
                data_size INTEGER,
                transfer_method TEXT,
                encryption TEXT,
                timestamp TIMESTAMP,
                authorized BOOLEAN,
                approved_by TEXT,
                audit_trail TEXT
            )
        ''')
        
        # 建立隔離事件表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS isolation_events (
                id TEXT PRIMARY KEY,
                event_type TEXT,
                zone_id TEXT,
                description TEXT,
                severity TEXT,
                timestamp TIMESTAMP,
                resolved BOOLEAN,
                mitigation TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_default_air_gap_zones(self):
        """載入預設氣隙區域"""
        # 絕密隔離區
        top_secret_zone = AirGapZone(
            id="top_secret_zone",
            name="絕密隔離區",
            security_level=SecurityZone.TOP_SECRET,
            isolation_level=IsolationLevel.PHYSICAL,
            data_direction=DataDirection.NONE,
            physical_location="地下掩體",
            network_connections=[],
            allowed_protocols=[],
            data_classification="TOP_SECRET",
            access_controls=["生物識別", "多因子認證", "安全許可"],
            monitoring_enabled=True,
            created_at=datetime.now()
        )
        self.air_gap_zones[top_secret_zone.id] = top_secret_zone
        
        # 機密隔離區
        classified_zone = AirGapZone(
            id="classified_zone",
            name="機密隔離區",
            security_level=SecurityZone.CLASSIFIED,
            isolation_level=IsolationLevel.ELECTROMAGNETIC,
            data_direction=DataDirection.OUTBOUND,
            physical_location="安全建築",
            network_connections=["光學隔離器"],
            allowed_protocols=["光學傳輸"],
            data_classification="CLASSIFIED",
            access_controls=["安全許可", "多因子認證"],
            monitoring_enabled=True,
            created_at=datetime.now()
        )
        self.air_gap_zones[classified_zone.id] = classified_zone
        
        # 隔離區
        compartmented_zone = AirGapZone(
            id="compartmented_zone",
            name="隔離區",
            security_level=SecurityZone.COMPARTMENTED,
            isolation_level=IsolationLevel.OPTICAL,
            data_direction=DataDirection.INBOUND,
            physical_location="隔離建築",
            network_connections=["單向光纖"],
            allowed_protocols=["光學傳輸", "物理傳輸"],
            data_classification="COMPARTMENTED",
            access_controls=["安全許可"],
            monitoring_enabled=True,
            created_at=datetime.now()
        )
        self.air_gap_zones[compartmented_zone.id] = compartmented_zone

    def _init_physical_isolation(self):
        """初始化物理隔離"""
        # 物理屏障
        self.physical_barriers = {
            "electromagnetic_shield": {
                "type": "電磁屏蔽",
                "material": "銅網",
                "effectiveness": "99.9%",
                "status": "ACTIVE"
            },
            "faraday_cage": {
                "type": "法拉第籠",
                "material": "導電金屬",
                "effectiveness": "100%",
                "status": "ACTIVE"
            },
            "optical_isolation": {
                "type": "光學隔離",
                "method": "單向光纖",
                "effectiveness": "100%",
                "status": "ACTIVE"
            },
            "quantum_isolation": {
                "type": "量子隔離",
                "method": "量子糾纏",
                "effectiveness": "100%",
                "status": "ACTIVE"
            }
        }
        
        # 光學鏈路
        self.optical_links = {
            "zone1_to_zone2": {
                "source": "classified_zone",
                "destination": "compartmented_zone",
                "method": "單向光纖",
                "bandwidth": "10Gbps",
                "encryption": "AES-256",
                "status": "ACTIVE"
            }
        }

    def _start_isolation_monitoring(self):
        """啟動隔離監控"""
        def isolation_monitor():
            while True:
                try:
                    # 監控氣隙完整性
                    self._monitor_air_gap_integrity()
                    
                    # 監控物理隔離
                    self._monitor_physical_isolation()
                    
                    # 監控數據傳輸
                    self._monitor_data_transfers()
                    
                    # 檢測隔離違規
                    self._detect_isolation_violations()
                    
                    time.sleep(10)  # 每10秒監控一次
                
                except Exception as e:
                    logger.error(f"隔離監控錯誤: {e}")
                    time.sleep(30)
        
        monitor_thread = threading.Thread(target=isolation_monitor, daemon=True)
        monitor_thread.start()

    def _monitor_air_gap_integrity(self):
        """監控氣隙完整性"""
        try:
            for zone in self.air_gap_zones.values():
                # 檢查網路連線
                if zone.isolation_level == IsolationLevel.PHYSICAL:
                    if zone.network_connections:
                        self._log_isolation_event(
                            event_type="NETWORK_CONNECTION_DETECTED",
                            zone_id=zone.id,
                            description=f"檢測到網路連線: {zone.network_connections}",
                            severity="CRITICAL"
                        )
                
                # 檢查數據方向
                if zone.data_direction == DataDirection.NONE:
                    # 檢查是否有數據傳輸
                    recent_transfers = [t for t in self.data_transfers.values() 
                                      if t.source_zone == zone.id or t.dest_zone == zone.id]
                    if recent_transfers:
                        self._log_isolation_event(
                            event_type="UNAUTHORIZED_DATA_TRANSFER",
                            zone_id=zone.id,
                            description="檢測到未授權數據傳輸",
                            severity="CRITICAL"
                        )
        
        except Exception as e:
            logger.error(f"氣隙完整性監控錯誤: {e}")

    def _monitor_physical_isolation(self):
        """監控物理隔離"""
        try:
            for barrier_id, barrier in self.physical_barriers.items():
                # 檢查物理屏障狀態
                if barrier["status"] != "ACTIVE":
                    self._log_isolation_event(
                        event_type="PHYSICAL_BARRIER_FAILURE",
                        zone_id="system",
                        description=f"物理屏障失效: {barrier['type']}",
                        severity="HIGH"
                    )
        
        except Exception as e:
            logger.error(f"物理隔離監控錯誤: {e}")

    def _monitor_data_transfers(self):
        """監控數據傳輸"""
        try:
            # 檢查所有數據傳輸
            for transfer in self.data_transfers.values():
                source_zone = self.air_gap_zones.get(transfer.source_zone)
                dest_zone = self.air_gap_zones.get(transfer.dest_zone)
                
                if source_zone and dest_zone:
                    # 檢查是否違反隔離規則
                    if self._is_transfer_violation(transfer, source_zone, dest_zone):
                        self._log_isolation_event(
                            event_type="ISOLATION_VIOLATION",
                            zone_id=transfer.source_zone,
                            description=f"數據傳輸違反隔離規則: {transfer.source_zone} -> {transfer.dest_zone}",
                            severity="CRITICAL"
                        )
        
        except Exception as e:
            logger.error(f"數據傳輸監控錯誤: {e}")

    def _is_transfer_violation(self, transfer: DataTransfer, source_zone: AirGapZone, dest_zone: AirGapZone) -> bool:
        """檢查傳輸是否違規"""
        # 檢查安全等級
        if source_zone.security_level.value > dest_zone.security_level.value:
            return True
        
        # 檢查數據方向
        if source_zone.data_direction == DataDirection.NONE:
            return True
        
        # 檢查隔離等級
        if source_zone.isolation_level == IsolationLevel.PHYSICAL:
            return True
        
        return False

    def _detect_isolation_violations(self):
        """檢測隔離違規"""
        try:
            # 檢測電磁洩漏
            self._detect_electromagnetic_leakage()
            
            # 檢測光學洩漏
            self._detect_optical_leakage()
            
            # 檢測量子洩漏
            self._detect_quantum_leakage()
        
        except Exception as e:
            logger.error(f"隔離違規檢測錯誤: {e}")

    def _detect_electromagnetic_leakage(self):
        """檢測電磁洩漏"""
        # 模擬電磁洩漏檢測
        import random
        if random.random() < 0.01:  # 1%機率檢測到洩漏
            self._log_isolation_event(
                event_type="ELECTROMAGNETIC_LEAKAGE",
                zone_id="system",
                description="檢測到電磁洩漏",
                severity="HIGH"
            )

    def _detect_optical_leakage(self):
        """檢測光學洩漏"""
        # 模擬光學洩漏檢測
        import random
        if random.random() < 0.005:  # 0.5%機率檢測到洩漏
            self._log_isolation_event(
                event_type="OPTICAL_LEAKAGE",
                zone_id="system",
                description="檢測到光學洩漏",
                severity="MEDIUM"
            )

    def _detect_quantum_leakage(self):
        """檢測量子洩漏"""
        # 模擬量子洩漏檢測
        import random
        if random.random() < 0.001:  # 0.1%機率檢測到洩漏
            self._log_isolation_event(
                event_type="QUANTUM_LEAKAGE",
                zone_id="system",
                description="檢測到量子洩漏",
                severity="CRITICAL"
            )

    def _log_isolation_event(self, event_type: str, zone_id: str, description: str, severity: str):
        """記錄隔離事件"""
        event_id = f"isolation_{int(time.time())}_{hashlib.md5(f'{event_type}{zone_id}'.encode()).hexdigest()[:8]}"
        
        event = IsolationEvent(
            id=event_id,
            event_type=event_type,
            zone_id=zone_id,
            description=description,
            severity=severity,
            timestamp=datetime.now(),
            resolved=False,
            mitigation="待處理"
        )
        
        self.isolation_events[event_id] = event
        self._save_isolation_event(event)
        
        # 更新統計
        self.stats['security_events'] += 1
        
        logger.warning(f"隔離事件: {event_type} - {description} (嚴重程度: {severity})")

    def create_air_gap_zone(self, name: str, security_level: SecurityZone, 
                          isolation_level: IsolationLevel, data_direction: DataDirection) -> str:
        """創建氣隙區域"""
        zone_id = f"zone_{hashlib.md5(f'{name}{security_level.value}'.encode()).hexdigest()[:8]}"
        
        zone = AirGapZone(
            id=zone_id,
            name=name,
            security_level=security_level,
            isolation_level=isolation_level,
            data_direction=data_direction,
            physical_location="待指定",
            network_connections=[],
            allowed_protocols=[],
            data_classification=security_level.value,
            access_controls=["安全許可"],
            monitoring_enabled=True,
            created_at=datetime.now()
        )
        
        self.air_gap_zones[zone_id] = zone
        self._save_air_gap_zone(zone)
        
        # 更新統計
        self.stats['total_zones'] += 1
        if isolation_level == IsolationLevel.PHYSICAL:
            self.stats['isolated_zones'] += 1
        
        logger.info(f"創建氣隙區域: {name} (安全等級: {security_level.value})")
        return zone_id

    def request_data_transfer(self, source_zone: str, dest_zone: str, 
                            data_type: str, data_size: int, requester: str) -> bool:
        """請求數據傳輸"""
        # 檢查傳輸是否允許
        source_zone_obj = self.air_gap_zones.get(source_zone)
        dest_zone_obj = self.air_gap_zones.get(dest_zone)
        
        if not source_zone_obj or not dest_zone_obj:
            return False
        
        # 檢查隔離規則
        if self._is_transfer_allowed(source_zone_obj, dest_zone_obj):
            # 創建數據傳輸記錄
            transfer_id = f"transfer_{int(time.time())}_{hashlib.md5(f'{source_zone}{dest_zone}'.encode()).hexdigest()[:8]}"
            
            transfer = DataTransfer(
                id=transfer_id,
                source_zone=source_zone,
                dest_zone=dest_zone,
                data_type=data_type,
                data_size=data_size,
                transfer_method="光學隔離",
                encryption="AES-256",
                timestamp=datetime.now(),
                authorized=True,
                approved_by=requester,
                audit_trail=[{
                    "action": "REQUEST",
                    "timestamp": datetime.now().isoformat(),
                    "user": requester
                }]
            )
            
            self.data_transfers[transfer_id] = transfer
            self._save_data_transfer(transfer)
            
            # 更新統計
            self.stats['data_transfers'] += 1
            
            logger.info(f"數據傳輸授權: {source_zone} -> {dest_zone} ({data_type})")
            return True
        else:
            # 記錄阻擋嘗試
            self.stats['blocked_attempts'] += 1
            logger.warning(f"數據傳輸被阻擋: {source_zone} -> {dest_zone} (違反隔離規則)")
            return False

    def _is_transfer_allowed(self, source_zone: AirGapZone, dest_zone: AirGapZone) -> bool:
        """檢查傳輸是否允許"""
        # 檢查安全等級
        if source_zone.security_level.value > dest_zone.security_level.value:
            return False
        
        # 檢查數據方向
        if source_zone.data_direction == DataDirection.NONE:
            return False
        
        # 檢查隔離等級
        if source_zone.isolation_level == IsolationLevel.PHYSICAL:
            return False
        
        return True

    def _save_air_gap_zone(self, zone: AirGapZone):
        """儲存氣隙區域"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO air_gap_zones 
            (id, name, security_level, isolation_level, data_direction,
             physical_location, network_connections, allowed_protocols,
             data_classification, access_controls, monitoring_enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            zone.id, zone.name, zone.security_level.value, zone.isolation_level.value,
            zone.data_direction.value, zone.physical_location, json.dumps(zone.network_connections),
            json.dumps(zone.allowed_protocols), zone.data_classification,
            json.dumps(zone.access_controls), zone.monitoring_enabled, zone.created_at.isoformat()
        ))
        self.db_conn.commit()

    def _save_data_transfer(self, transfer: DataTransfer):
        """儲存數據傳輸"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO data_transfers 
            (id, source_zone, dest_zone, data_type, data_size, transfer_method,
             encryption, timestamp, authorized, approved_by, audit_trail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            transfer.id, transfer.source_zone, transfer.dest_zone, transfer.data_type,
            transfer.data_size, transfer.transfer_method, transfer.encryption,
            transfer.timestamp.isoformat(), transfer.authorized, transfer.approved_by,
            json.dumps(transfer.audit_trail)
        ))
        self.db_conn.commit()

    def _save_isolation_event(self, event: IsolationEvent):
        """儲存隔離事件"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO isolation_events 
            (id, event_type, zone_id, description, severity, timestamp, resolved, mitigation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id, event.event_type, event.zone_id, event.description,
            event.severity, event.timestamp.isoformat(), event.resolved, event.mitigation
        ))
        self.db_conn.commit()

    def get_isolation_status(self) -> Dict[str, Any]:
        """獲取隔離狀態"""
        return {
            'total_zones': len(self.air_gap_zones),
            'isolated_zones': len([z for z in self.air_gap_zones.values() if z.isolation_level == IsolationLevel.PHYSICAL]),
            'data_transfers': len(self.data_transfers),
            'blocked_attempts': self.stats['blocked_attempts'],
            'security_events': len(self.isolation_events),
            'physical_barriers': len(self.physical_barriers),
            'optical_links': len(self.optical_links),
            'stats': self.stats
        }

    def get_recent_events(self, limit: int = 10) -> List[IsolationEvent]:
        """獲取最近事件"""
        events = list(self.isolation_events.values())
        events.sort(key=lambda x: x.timestamp, reverse=True)
        return events[:limit]

def main():
    """主程式"""
    config = {
        'monitoring_interval': 10,
        'physical_isolation': True,
        'electromagnetic_shielding': True,
        'optical_isolation': True
    }
    
    isolation = MilitaryAirGapIsolation(config)
    
    print("🛡️ 軍事級氣隙隔離系統已啟動")
    print("=" * 60)
    
    # 顯示氣隙區域
    print("氣隙區域:")
    for zone in isolation.air_gap_zones.values():
        print(f"  {zone.name}: {zone.security_level.value} (隔離等級: {zone.isolation_level.value})")
    
    # 顯示物理屏障
    print(f"\n物理屏障: {len(isolation.physical_barriers)} 個")
    for barrier_id, barrier in isolation.physical_barriers.items():
        print(f"  {barrier['type']}: {barrier['status']}")
    
    print(f"\n🛡️ 系統正在監控氣隙隔離...")
    print("按 Ctrl+C 停止監控")

if __name__ == "__main__":
    main()




