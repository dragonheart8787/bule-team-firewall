#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理和規則引擎
Configuration Management and Rules Engine

功能特色：
- 動態配置管理
- 規則引擎
- 配置驗證
- 版本控制
- 備份恢復
- 軍事級安全配置
"""

import json
import yaml
import logging
import hashlib
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import os
import threading
import time
from pathlib import Path
import copy

logger = logging.getLogger(__name__)

class ConfigType(Enum):
    """配置類型"""
    FIREWALL = "FIREWALL"
    IDS = "IDS"
    THREAT_INTEL = "THREAT_INTEL"
    LOGGING = "LOGGING"
    SYSTEM = "SYSTEM"
    SECURITY = "SECURITY"

class RuleType(Enum):
    """規則類型"""
    FILTER = "FILTER"
    DETECTION = "DETECTION"
    RESPONSE = "RESPONSE"
    NOTIFICATION = "NOTIFICATION"
    QUARANTINE = "QUARANTINE"

class ConfigStatus(Enum):
    """配置狀態"""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    PENDING = "PENDING"
    ERROR = "ERROR"
    ROLLBACK = "ROLLBACK"

@dataclass
class Configuration:
    """配置物件"""
    id: str
    name: str
    config_type: ConfigType
    data: Dict[str, Any]
    version: str
    created_at: datetime
    updated_at: datetime
    status: ConfigStatus
    description: str
    tags: List[str]
    checksum: str
    parent_id: Optional[str] = None

@dataclass
class Rule:
    """規則物件"""
    id: str
    name: str
    rule_type: RuleType
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    description: str
    tags: List[str]

@dataclass
class ConfigBackup:
    """配置備份"""
    id: str
    name: str
    config_id: str
    backup_data: Dict[str, Any]
    created_at: datetime
    checksum: str
    size: int

class ConfigurationManager:
    """配置管理器"""
    
    def __init__(self, config_dir: str = "configs"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.configurations: Dict[str, Configuration] = {}
        self.rules: Dict[str, Rule] = {}
        self.backups: Dict[str, ConfigBackup] = {}
        
        # 配置鎖
        self.config_lock = threading.RLock()
        
        # 初始化資料庫
        self._init_database()
        
        # 載入現有配置
        self._load_configurations()
        self._load_rules()
        
        logger.info("配置管理器初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('config_manager.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立配置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configurations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                config_type TEXT,
                data TEXT,
                version TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                status TEXT,
                description TEXT,
                tags TEXT,
                checksum TEXT,
                parent_id TEXT
            )
        ''')
        
        # 建立規則表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                rule_type TEXT,
                conditions TEXT,
                actions TEXT,
                priority INTEGER,
                enabled BOOLEAN,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                description TEXT,
                tags TEXT
            )
        ''')
        
        # 建立備份表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config_backups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                config_id TEXT,
                backup_data TEXT,
                created_at TIMESTAMP,
                checksum TEXT,
                size INTEGER
            )
        ''')
        
        # 建立配置歷史表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_id TEXT,
                action TEXT,
                old_data TEXT,
                new_data TEXT,
                timestamp TIMESTAMP,
                user TEXT,
                reason TEXT
            )
        ''')
        
        self.db_conn.commit()

    def _load_configurations(self):
        """載入配置"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM configurations')
        rows = cursor.fetchall()
        
        for row in rows:
            config = Configuration(
                id=row[0],
                name=row[1],
                config_type=ConfigType(row[2]),
                data=json.loads(row[3]),
                version=row[4],
                created_at=datetime.fromisoformat(row[5]),
                updated_at=datetime.fromisoformat(row[6]),
                status=ConfigStatus(row[7]),
                description=row[8],
                tags=json.loads(row[9]) if row[9] else [],
                checksum=row[10],
                parent_id=row[11]
            )
            self.configurations[config.id] = config

    def _load_rules(self):
        """載入規則"""
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM rules')
        rows = cursor.fetchall()
        
        for row in rows:
            rule = Rule(
                id=row[0],
                name=row[1],
                rule_type=RuleType(row[2]),
                conditions=json.loads(row[3]),
                actions=json.loads(row[4]),
                priority=row[5],
                enabled=bool(row[6]),
                created_at=datetime.fromisoformat(row[7]),
                updated_at=datetime.fromisoformat(row[8]),
                description=row[9],
                tags=json.loads(row[10]) if row[10] else []
            )
            self.rules[rule.id] = rule

    def create_configuration(self, name: str, config_type: ConfigType, 
                           data: Dict[str, Any], description: str = "", 
                           tags: List[str] = None) -> Configuration:
        """建立新配置"""
        with self.config_lock:
            config_id = self._generate_config_id(name)
            version = "1.0.0"
            checksum = self._calculate_checksum(data)
            
            config = Configuration(
                id=config_id,
                name=name,
                config_type=config_type,
                data=data,
                version=version,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                status=ConfigStatus.PENDING,
                description=description,
                tags=tags or [],
                checksum=checksum
            )
            
            # 驗證配置
            if not self._validate_configuration(config):
                raise ValueError("配置驗證失敗")
            
            # 儲存配置
            self._save_configuration(config)
            self.configurations[config_id] = config
            
            # 記錄歷史
            self._log_config_change(config_id, "CREATE", None, data)
            
            logger.info(f"已建立配置: {name}")
            return config

    def update_configuration(self, config_id: str, data: Dict[str, Any], 
                           description: str = None) -> Configuration:
        """更新配置"""
        with self.config_lock:
            if config_id not in self.configurations:
                raise ValueError(f"配置不存在: {config_id}")
            
            old_config = self.configurations[config_id]
            old_data = copy.deepcopy(old_config.data)
            
            # 建立新版本
            new_version = self._increment_version(old_config.version)
            new_checksum = self._calculate_checksum(data)
            
            updated_config = Configuration(
                id=config_id,
                name=old_config.name,
                config_type=old_config.config_type,
                data=data,
                version=new_version,
                created_at=old_config.created_at,
                updated_at=datetime.now(),
                status=ConfigStatus.PENDING,
                description=description or old_config.description,
                tags=old_config.tags,
                checksum=new_checksum,
                parent_id=old_config.id
            )
            
            # 驗證配置
            if not self._validate_configuration(updated_config):
                raise ValueError("配置驗證失敗")
            
            # 備份舊配置
            self._create_backup(old_config)
            
            # 儲存新配置
            self._save_configuration(updated_config)
            self.configurations[config_id] = updated_config
            
            # 記錄歷史
            self._log_config_change(config_id, "UPDATE", old_data, data)
            
            logger.info(f"已更新配置: {old_config.name}")
            return updated_config

    def delete_configuration(self, config_id: str):
        """刪除配置"""
        with self.config_lock:
            if config_id not in self.configurations:
                raise ValueError(f"配置不存在: {config_id}")
            
            config = self.configurations[config_id]
            
            # 建立備份
            self._create_backup(config)
            
            # 從資料庫刪除
            cursor = self.db_conn.cursor()
            cursor.execute('DELETE FROM configurations WHERE id = ?', (config_id,))
            self.db_conn.commit()
            
            # 從記憶體刪除
            del self.configurations[config_id]
            
            # 記錄歷史
            self._log_config_change(config_id, "DELETE", config.data, None)
            
            logger.info(f"已刪除配置: {config.name}")

    def activate_configuration(self, config_id: str) -> bool:
        """啟用配置"""
        with self.config_lock:
            if config_id not in self.configurations:
                return False
            
            config = self.configurations[config_id]
            
            # 停用同類型的其他配置
            for other_config in self.configurations.values():
                if (other_config.config_type == config.config_type and 
                    other_config.id != config_id and 
                    other_config.status == ConfigStatus.ACTIVE):
                    other_config.status = ConfigStatus.INACTIVE
                    self._save_configuration(other_config)
            
            # 啟用配置
            config.status = ConfigStatus.ACTIVE
            config.updated_at = datetime.now()
            self._save_configuration(config)
            
            logger.info(f"已啟用配置: {config.name}")
            return True

    def deactivate_configuration(self, config_id: str) -> bool:
        """停用配置"""
        with self.config_lock:
            if config_id not in self.configurations:
                return False
            
            config = self.configurations[config_id]
            config.status = ConfigStatus.INACTIVE
            config.updated_at = datetime.now()
            self._save_configuration(config)
            
            logger.info(f"已停用配置: {config.name}")
            return True

    def create_rule(self, name: str, rule_type: RuleType, 
                   conditions: List[Dict[str, Any]], actions: List[Dict[str, Any]],
                   priority: int = 0, description: str = "", 
                   tags: List[str] = None) -> Rule:
        """建立規則"""
        rule_id = self._generate_rule_id(name)
        
        rule = Rule(
            id=rule_id,
            name=name,
            rule_type=rule_type,
            conditions=conditions,
            actions=actions,
            priority=priority,
            enabled=True,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            description=description,
            tags=tags or []
        )
        
        # 驗證規則
        if not self._validate_rule(rule):
            raise ValueError("規則驗證失敗")
        
        # 儲存規則
        self._save_rule(rule)
        self.rules[rule_id] = rule
        
        logger.info(f"已建立規則: {name}")
        return rule

    def update_rule(self, rule_id: str, conditions: List[Dict[str, Any]] = None,
                   actions: List[Dict[str, Any]] = None, priority: int = None,
                   enabled: bool = None, description: str = None) -> Rule:
        """更新規則"""
        if rule_id not in self.rules:
            raise ValueError(f"規則不存在: {rule_id}")
        
        rule = self.rules[rule_id]
        
        # 更新欄位
        if conditions is not None:
            rule.conditions = conditions
        if actions is not None:
            rule.actions = actions
        if priority is not None:
            rule.priority = priority
        if enabled is not None:
            rule.enabled = enabled
        if description is not None:
            rule.description = description
        
        rule.updated_at = datetime.now()
        
        # 驗證規則
        if not self._validate_rule(rule):
            raise ValueError("規則驗證失敗")
        
        # 儲存規則
        self._save_rule(rule)
        
        logger.info(f"已更新規則: {rule.name}")
        return rule

    def delete_rule(self, rule_id: str):
        """刪除規則"""
        if rule_id not in self.rules:
            raise ValueError(f"規則不存在: {rule_id}")
        
        rule = self.rules[rule_id]
        
        # 從資料庫刪除
        cursor = self.db_conn.cursor()
        cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        self.db_conn.commit()
        
        # 從記憶體刪除
        del self.rules[rule_id]
        
        logger.info(f"已刪除規則: {rule.name}")

    def evaluate_rules(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """評估規則"""
        triggered_actions = []
        
        # 按優先級排序規則
        sorted_rules = sorted(self.rules.values(), key=lambda x: x.priority, reverse=True)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            # 檢查條件
            if self._evaluate_conditions(rule.conditions, context):
                # 執行動作
                for action in rule.actions:
                    triggered_actions.append({
                        'rule_id': rule.id,
                        'rule_name': rule.name,
                        'action': action,
                        'timestamp': datetime.now()
                    })
        
        return triggered_actions

    def export_configuration(self, config_id: str, format: str = "yaml") -> str:
        """匯出配置"""
        if config_id not in self.configurations:
            raise ValueError(f"配置不存在: {config_id}")
        
        config = self.configurations[config_id]
        
        if format == "yaml":
            return yaml.dump(config.data, default_flow_style=False, allow_unicode=True)
        elif format == "json":
            return json.dumps(config.data, indent=2, ensure_ascii=False)
        else:
            raise ValueError(f"不支援的格式: {format}")

    def import_configuration(self, data: str, name: str, config_type: ConfigType,
                           format: str = "yaml", description: str = "") -> Configuration:
        """匯入配置"""
        try:
            if format == "yaml":
                config_data = yaml.safe_load(data)
            elif format == "json":
                config_data = json.loads(data)
            else:
                raise ValueError(f"不支援的格式: {format}")
            
            return self.create_configuration(name, config_type, config_data, description)
        
        except Exception as e:
            raise ValueError(f"匯入配置失敗: {e}")

    def create_backup(self, config_id: str, name: str = None) -> ConfigBackup:
        """建立配置備份"""
        if config_id not in self.configurations:
            raise ValueError(f"配置不存在: {config_id}")
        
        config = self.configurations[config_id]
        backup_name = name or f"{config.name}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup = ConfigBackup(
            id=self._generate_backup_id(backup_name),
            name=backup_name,
            config_id=config_id,
            backup_data=copy.deepcopy(config.data),
            created_at=datetime.now(),
            checksum=self._calculate_checksum(config.data),
            size=len(json.dumps(config.data))
        )
        
        self._save_backup(backup)
        self.backups[backup.id] = backup
        
        logger.info(f"已建立配置備份: {backup_name}")
        return backup

    def restore_backup(self, backup_id: str) -> Configuration:
        """恢復配置備份"""
        if backup_id not in self.backups:
            raise ValueError(f"備份不存在: {backup_id}")
        
        backup = self.backups[backup_id]
        config_id = backup.config_id
        
        if config_id not in self.configurations:
            raise ValueError(f"配置不存在: {config_id}")
        
        config = self.configurations[config_id]
        
        # 建立當前配置的備份
        self._create_backup(config)
        
        # 恢復配置
        config.data = copy.deepcopy(backup.backup_data)
        config.updated_at = datetime.now()
        config.checksum = backup.checksum
        
        self._save_configuration(config)
        
        logger.info(f"已恢復配置備份: {backup.name}")
        return config

    def get_configuration_history(self, config_id: str, limit: int = 50) -> List[Dict]:
        """獲取配置歷史"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            SELECT * FROM config_history 
            WHERE config_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (config_id, limit))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                'id': row[0],
                'config_id': row[1],
                'action': row[2],
                'old_data': json.loads(row[3]) if row[3] else None,
                'new_data': json.loads(row[4]) if row[4] else None,
                'timestamp': row[5],
                'user': row[6],
                'reason': row[7]
            })
        
        return history

    def _save_configuration(self, config: Configuration):
        """儲存配置到資料庫"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO configurations 
            (id, name, config_type, data, version, created_at, updated_at, 
             status, description, tags, checksum, parent_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            config.id, config.name, config.config_type.value, json.dumps(config.data),
            config.version, config.created_at.isoformat(), config.updated_at.isoformat(),
            config.status.value, config.description, json.dumps(config.tags),
            config.checksum, config.parent_id
        ))
        self.db_conn.commit()

    def _save_rule(self, rule: Rule):
        """儲存規則到資料庫"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO rules 
            (id, name, rule_type, conditions, actions, priority, enabled, 
             created_at, updated_at, description, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule.id, rule.name, rule.rule_type.value, json.dumps(rule.conditions),
            json.dumps(rule.actions), rule.priority, rule.enabled,
            rule.created_at.isoformat(), rule.updated_at.isoformat(),
            rule.description, json.dumps(rule.tags)
        ))
        self.db_conn.commit()

    def _save_backup(self, backup: ConfigBackup):
        """儲存備份到資料庫"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO config_backups 
            (id, name, config_id, backup_data, created_at, checksum, size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            backup.id, backup.name, backup.config_id, json.dumps(backup.backup_data),
            backup.created_at.isoformat(), backup.checksum, backup.size
        ))
        self.db_conn.commit()

    def _create_backup(self, config: Configuration):
        """建立配置備份"""
        backup_name = f"{config.name}_auto_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.create_backup(config.id, backup_name)

    def _validate_configuration(self, config: Configuration) -> bool:
        """驗證配置"""
        try:
            # 基本驗證
            if not config.name or not config.data:
                return False
            
            # 根據配置類型進行特定驗證
            if config.config_type == ConfigType.FIREWALL:
                return self._validate_firewall_config(config.data)
            elif config.config_type == ConfigType.IDS:
                return self._validate_ids_config(config.data)
            elif config.config_type == ConfigType.THREAT_INTEL:
                return self._validate_threat_intel_config(config.data)
            
            return True
        
        except Exception as e:
            logger.error(f"配置驗證錯誤: {e}")
            return False

    def _validate_firewall_config(self, data: Dict[str, Any]) -> bool:
        """驗證防火牆配置"""
        required_fields = ['interface', 'monitoring_mode', 'auto_block']
        return all(field in data for field in required_fields)

    def _validate_ids_config(self, data: Dict[str, Any]) -> bool:
        """驗證IDS配置"""
        required_fields = ['enabled', 'signature_database']
        return all(field in data for field in required_fields)

    def _validate_threat_intel_config(self, data: Dict[str, Any]) -> bool:
        """驗證威脅情報配置"""
        required_fields = ['enabled', 'update_interval']
        return all(field in data for field in required_fields)

    def _validate_rule(self, rule: Rule) -> bool:
        """驗證規則"""
        try:
            # 基本驗證
            if not rule.name or not rule.conditions or not rule.actions:
                return False
            
            # 驗證條件格式
            for condition in rule.conditions:
                if not isinstance(condition, dict) or 'field' not in condition:
                    return False
            
            # 驗證動作格式
            for action in rule.actions:
                if not isinstance(action, dict) or 'type' not in action:
                    return False
            
            return True
        
        except Exception as e:
            logger.error(f"規則驗證錯誤: {e}")
            return False

    def _evaluate_conditions(self, conditions: List[Dict[str, Any]], 
                           context: Dict[str, Any]) -> bool:
        """評估條件"""
        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator', 'eq')
            value = condition.get('value')
            
            if field not in context:
                return False
            
            context_value = context[field]
            
            if not self._evaluate_condition(context_value, operator, value):
                return False
        
        return True

    def _evaluate_condition(self, context_value: Any, operator: str, value: Any) -> bool:
        """評估單個條件"""
        if operator == 'eq':
            return context_value == value
        elif operator == 'ne':
            return context_value != value
        elif operator == 'gt':
            return context_value > value
        elif operator == 'lt':
            return context_value < value
        elif operator == 'gte':
            return context_value >= value
        elif operator == 'lte':
            return context_value <= value
        elif operator == 'in':
            return context_value in value
        elif operator == 'not_in':
            return context_value not in value
        elif operator == 'contains':
            return value in str(context_value)
        elif operator == 'regex':
            import re
            return bool(re.search(value, str(context_value)))
        else:
            return False

    def _generate_config_id(self, name: str) -> str:
        """生成配置ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"config_{name}_{timestamp}"

    def _generate_rule_id(self, name: str) -> str:
        """生成規則ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"rule_{name}_{timestamp}"

    def _generate_backup_id(self, name: str) -> str:
        """生成備份ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"backup_{name}_{timestamp}"

    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        """計算配置校驗和"""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()

    def _increment_version(self, version: str) -> str:
        """增加版本號"""
        try:
            parts = version.split('.')
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
            patch += 1
            return f"{major}.{minor}.{patch}"
        except:
            return "1.0.1"

    def _log_config_change(self, config_id: str, action: str, old_data: Any, new_data: Any):
        """記錄配置變更"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO config_history 
            (config_id, action, old_data, new_data, timestamp, user, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            config_id, action, 
            json.dumps(old_data) if old_data else None,
            json.dumps(new_data) if new_data else None,
            datetime.now().isoformat(),
            "system",
            f"自動{action}操作"
        ))
        self.db_conn.commit()

    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        return {
            'configurations_count': len(self.configurations),
            'active_configurations': len([c for c in self.configurations.values() if c.status == ConfigStatus.ACTIVE]),
            'rules_count': len(self.rules),
            'enabled_rules': len([r for r in self.rules.values() if r.enabled]),
            'backups_count': len(self.backups),
            'config_types': {
                config_type.value: len([c for c in self.configurations.values() if c.config_type == config_type])
                for config_type in ConfigType
            }
        }

def main():
    """主程式"""
    # 建立配置管理器
    config_manager = ConfigurationManager()
    
    # 建立範例配置
    firewall_config = {
        'interface': 'eth0',
        'monitoring_mode': True,
        'auto_block': True,
        'threat_threshold': 0.7
    }
    
    config = config_manager.create_configuration(
        name="預設防火牆配置",
        config_type=ConfigType.FIREWALL,
        data=firewall_config,
        description="系統預設防火牆配置"
    )
    
    # 建立範例規則
    rule = config_manager.create_rule(
        name="高威脅自動阻擋",
        rule_type=RuleType.RESPONSE,
        conditions=[
            {'field': 'threat_score', 'operator': 'gte', 'value': 0.8}
        ],
        actions=[
            {'type': 'block_ip', 'value': 'source_ip'},
            {'type': 'send_alert', 'value': 'HIGH_THREAT_DETECTED'}
        ],
        priority=100,
        description="自動阻擋高威脅IP"
    )
    
    # 測試規則評估
    context = {
        'threat_score': 0.9,
        'source_ip': '192.168.1.100'
    }
    
    triggered_actions = config_manager.evaluate_rules(context)
    print(f"觸發的動作: {triggered_actions}")
    
    # 顯示統計資訊
    stats = config_manager.get_statistics()
    print(f"統計資訊: {stats}")

if __name__ == "__main__":
    main()

