#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日誌記錄和審計系統
Logging and Audit System

功能特色：
- 結構化日誌記錄
- 審計追蹤
- 日誌輪轉
- 安全日誌
- 合規報告
- 軍事級日誌保護
"""

import json
import logging
import logging.handlers
import hashlib
import hmac
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import os
import gzip
import shutil
from pathlib import Path
import structlog
import psutil
import socket

logger = logging.getLogger(__name__)

class LogLevel(Enum):
    """日誌等級"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"
    AUDIT = "AUDIT"

class EventType(Enum):
    """事件類型"""
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    CONFIGURATION = "CONFIGURATION"
    NETWORK = "NETWORK"
    SECURITY = "SECURITY"
    SYSTEM = "SYSTEM"
    THREAT = "THREAT"
    COMPLIANCE = "COMPLIANCE"

class AuditAction(Enum):
    """審計動作"""
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    READ = "READ"
    EXECUTE = "EXECUTE"
    CONFIGURE = "CONFIGURE"
    ACCESS = "ACCESS"
    DENY = "DENY"

@dataclass
class LogEntry:
    """日誌條目"""
    timestamp: datetime
    level: LogLevel
    event_type: EventType
    message: str
    source: str
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Dict[str, Any]
    correlation_id: Optional[str]
    severity: int
    classification: str

@dataclass
class AuditEntry:
    """審計條目"""
    timestamp: datetime
    action: AuditAction
    resource: str
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    result: str  # SUCCESS, FAILURE, DENIED
    details: Dict[str, Any]
    risk_level: str
    compliance_tags: List[str]

class AuditLogger:
    """審計日誌器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.log_dir = Path(config.get('log_dir', 'logs'))
        self.log_dir.mkdir(exist_ok=True)
        
        # 日誌佇列
        self.log_queue = []
        self.audit_queue = []
        self.queue_lock = threading.Lock()
        
        # 初始化資料庫
        self._init_database()
        
        # 設定結構化日誌
        self._setup_structured_logging()
        
        # 啟動背景處理
        self._start_background_processing()
        
        logger.info("審計日誌系統初始化完成")

    def _init_database(self):
        """初始化資料庫"""
        self.db_conn = sqlite3.connect('audit_logs.db', check_same_thread=False)
        cursor = self.db_conn.cursor()
        
        # 建立日誌表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                level TEXT,
                event_type TEXT,
                message TEXT,
                source TEXT,
                user_id TEXT,
                session_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                correlation_id TEXT,
                severity INTEGER,
                classification TEXT,
                checksum TEXT
            )
        ''')
        
        # 建立審計表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                action TEXT,
                resource TEXT,
                user_id TEXT,
                session_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                result TEXT,
                details TEXT,
                risk_level TEXT,
                compliance_tags TEXT,
                checksum TEXT
            )
        ''')
        
        # 建立索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_entries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_level ON log_entries(level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_event_type ON log_entries(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_entries(user_id)')
        
        self.db_conn.commit()

    def _setup_structured_logging(self):
        """設定結構化日誌"""
        # 設定structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # 建立安全日誌處理器
        self.security_logger = structlog.get_logger("security")
        self.audit_logger = structlog.get_logger("audit")

    def _start_background_processing(self):
        """啟動背景處理"""
        # 日誌處理線程
        log_thread = threading.Thread(target=self._process_logs, daemon=True)
        log_thread.start()
        
        # 審計處理線程
        audit_thread = threading.Thread(target=self._process_audits, daemon=True)
        audit_thread.start()
        
        # 日誌輪轉線程
        rotation_thread = threading.Thread(target=self._rotate_logs, daemon=True)
        rotation_thread.start()

    def log_event(self, level: LogLevel, event_type: EventType, message: str,
                 source: str, user_id: str = None, session_id: str = None,
                 ip_address: str = None, user_agent: str = None,
                 details: Dict[str, Any] = None, correlation_id: str = None,
                 classification: str = "UNCLASSIFIED"):
        """記錄事件"""
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            event_type=event_type,
            message=message,
            source=source,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
            correlation_id=correlation_id,
            severity=self._get_severity(level),
            classification=classification
        )
        
        with self.queue_lock:
            self.log_queue.append(log_entry)
        
        # 即時記錄到結構化日誌
        self._log_to_structured(log_entry)

    def audit_event(self, action: AuditAction, resource: str, user_id: str,
                   session_id: str, ip_address: str, user_agent: str,
                   result: str, details: Dict[str, Any] = None,
                   risk_level: str = "MEDIUM", compliance_tags: List[str] = None):
        """記錄審計事件"""
        audit_entry = AuditEntry(
            timestamp=datetime.now(),
            action=action,
            resource=resource,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            result=result,
            details=details or {},
            risk_level=risk_level,
            compliance_tags=compliance_tags or []
        )
        
        with self.queue_lock:
            self.audit_queue.append(audit_entry)
        
        # 即時記錄到結構化日誌
        self._audit_to_structured(audit_entry)

    def _process_logs(self):
        """處理日誌佇列"""
        while True:
            try:
                with self.queue_lock:
                    if self.log_queue:
                        batch = self.log_queue[:100]  # 批次處理100條
                        self.log_queue = self.log_queue[100:]
                    else:
                        batch = []
                
                if batch:
                    self._save_logs_to_db(batch)
                    self._write_logs_to_file(batch)
                
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"處理日誌錯誤: {e}")
                time.sleep(5)

    def _process_audits(self):
        """處理審計佇列"""
        while True:
            try:
                with self.queue_lock:
                    if self.audit_queue:
                        batch = self.audit_queue[:100]  # 批次處理100條
                        self.audit_queue = self.audit_queue[100:]
                    else:
                        batch = []
                
                if batch:
                    self._save_audits_to_db(batch)
                    self._write_audits_to_file(batch)
                
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"處理審計錯誤: {e}")
                time.sleep(5)

    def _save_logs_to_db(self, logs: List[LogEntry]):
        """儲存日誌到資料庫"""
        cursor = self.db_conn.cursor()
        
        for log in logs:
            checksum = self._calculate_checksum(log)
            cursor.execute('''
                INSERT INTO log_entries 
                (timestamp, level, event_type, message, source, user_id, session_id,
                 ip_address, user_agent, details, correlation_id, severity, classification, checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log.timestamp.isoformat(),
                log.level.value,
                log.event_type.value,
                log.message,
                log.source,
                log.user_id,
                log.session_id,
                log.ip_address,
                log.user_agent,
                json.dumps(log.details, ensure_ascii=False),
                log.correlation_id,
                log.severity,
                log.classification,
                checksum
            ))
        
        self.db_conn.commit()

    def _save_audits_to_db(self, audits: List[AuditEntry]):
        """儲存審計到資料庫"""
        cursor = self.db_conn.cursor()
        
        for audit in audits:
            checksum = self._calculate_audit_checksum(audit)
            cursor.execute('''
                INSERT INTO audit_entries 
                (timestamp, action, resource, user_id, session_id, ip_address,
                 user_agent, result, details, risk_level, compliance_tags, checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                audit.timestamp.isoformat(),
                audit.action.value,
                audit.resource,
                audit.user_id,
                audit.session_id,
                audit.ip_address,
                audit.user_agent,
                audit.result,
                json.dumps(audit.details, ensure_ascii=False),
                audit.risk_level,
                json.dumps(audit.compliance_tags, ensure_ascii=False),
                checksum
            ))
        
        self.db_conn.commit()

    def _write_logs_to_file(self, logs: List[LogEntry]):
        """寫入日誌檔案"""
        log_file = self.log_dir / f"firewall_{datetime.now().strftime('%Y%m%d')}.log"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            for log in logs:
                log_line = self._format_log_line(log)
                f.write(log_line + '\n')

    def _write_audits_to_file(self, audits: List[AuditEntry]):
        """寫入審計檔案"""
        audit_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        
        with open(audit_file, 'a', encoding='utf-8') as f:
            for audit in audits:
                audit_line = self._format_audit_line(audit)
                f.write(audit_line + '\n')

    def _format_log_line(self, log: LogEntry) -> str:
        """格式化日誌行"""
        return json.dumps({
            'timestamp': log.timestamp.isoformat(),
            'level': log.level.value,
            'event_type': log.event_type.value,
            'message': log.message,
            'source': log.source,
            'user_id': log.user_id,
            'session_id': log.session_id,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'details': log.details,
            'correlation_id': log.correlation_id,
            'severity': log.severity,
            'classification': log.classification
        }, ensure_ascii=False)

    def _format_audit_line(self, audit: AuditEntry) -> str:
        """格式化審計行"""
        return json.dumps({
            'timestamp': audit.timestamp.isoformat(),
            'action': audit.action.value,
            'resource': audit.resource,
            'user_id': audit.user_id,
            'session_id': audit.session_id,
            'ip_address': audit.ip_address,
            'user_agent': audit.user_agent,
            'result': audit.result,
            'details': audit.details,
            'risk_level': audit.risk_level,
            'compliance_tags': audit.compliance_tags
        }, ensure_ascii=False)

    def _log_to_structured(self, log: LogEntry):
        """記錄到結構化日誌"""
        logger_func = getattr(self.security_logger, log.level.value.lower())
        logger_func(
            log.message,
            event_type=log.event_type.value,
            source=log.source,
            user_id=log.user_id,
            session_id=log.session_id,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            details=log.details,
            correlation_id=log.correlation_id,
            severity=log.severity,
            classification=log.classification
        )

    def _audit_to_structured(self, audit: AuditEntry):
        """記錄到結構化審計日誌"""
        self.audit_logger.info(
            f"審計事件: {audit.action.value}",
            action=audit.action.value,
            resource=audit.resource,
            user_id=audit.user_id,
            session_id=audit.session_id,
            ip_address=audit.ip_address,
            user_agent=audit.user_agent,
            result=audit.result,
            details=audit.details,
            risk_level=audit.risk_level,
            compliance_tags=audit.compliance_tags
        )

    def _rotate_logs(self):
        """日誌輪轉"""
        while True:
            try:
                # 每天檢查一次
                time.sleep(86400)
                
                # 壓縮舊日誌檔案
                self._compress_old_logs()
                
                # 刪除過期日誌
                self._cleanup_old_logs()
                
                # 清理資料庫舊記錄
                self._cleanup_old_db_records()
            
            except Exception as e:
                logger.error(f"日誌輪轉錯誤: {e}")

    def _compress_old_logs(self):
        """壓縮舊日誌檔案"""
        cutoff_date = datetime.now() - timedelta(days=1)
        
        for log_file in self.log_dir.glob("*.log"):
            if log_file.stat().st_mtime < cutoff_date.timestamp():
                # 壓縮檔案
                compressed_file = log_file.with_suffix('.log.gz')
                with open(log_file, 'rb') as f_in:
                    with gzip.open(compressed_file, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # 刪除原始檔案
                log_file.unlink()
                logger.info(f"已壓縮日誌檔案: {log_file.name}")

    def _cleanup_old_logs(self):
        """清理過期日誌"""
        retention_days = self.config.get('retention_days', 30)
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        for log_file in self.log_dir.glob("*.log.gz"):
            if log_file.stat().st_mtime < cutoff_date.timestamp():
                log_file.unlink()
                logger.info(f"已刪除過期日誌: {log_file.name}")

    def _cleanup_old_db_records(self):
        """清理資料庫舊記錄"""
        retention_days = self.config.get('retention_days', 30)
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        cursor = self.db_conn.cursor()
        
        # 清理日誌記錄
        cursor.execute('DELETE FROM log_entries WHERE timestamp < ?', 
                      (cutoff_date.isoformat(),))
        
        # 清理審計記錄
        cursor.execute('DELETE FROM audit_entries WHERE timestamp < ?', 
                      (cutoff_date.isoformat(),))
        
        self.db_conn.commit()
        
        logger.info(f"已清理 {retention_days} 天前的資料庫記錄")

    def _get_severity(self, level: LogLevel) -> int:
        """獲取嚴重程度數值"""
        severity_map = {
            LogLevel.DEBUG: 1,
            LogLevel.INFO: 2,
            LogLevel.WARNING: 3,
            LogLevel.ERROR: 4,
            LogLevel.CRITICAL: 5,
            LogLevel.SECURITY: 6,
            LogLevel.AUDIT: 7
        }
        return severity_map.get(level, 2)

    def _calculate_checksum(self, log: LogEntry) -> str:
        """計算日誌校驗和"""
        data = f"{log.timestamp}{log.level}{log.message}{log.source}{log.user_id}"
        return hashlib.md5(data.encode()).hexdigest()

    def _calculate_audit_checksum(self, audit: AuditEntry) -> str:
        """計算審計校驗和"""
        data = f"{audit.timestamp}{audit.action}{audit.resource}{audit.user_id}{audit.result}"
        return hashlib.md5(data.encode()).hexdigest()

    def search_logs(self, start_time: datetime = None, end_time: datetime = None,
                   level: LogLevel = None, event_type: EventType = None,
                   source: str = None, user_id: str = None,
                   limit: int = 1000) -> List[Dict]:
        """搜尋日誌"""
        cursor = self.db_conn.cursor()
        
        query = "SELECT * FROM log_entries WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        if level:
            query += " AND level = ?"
            params.append(level.value)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if source:
            query += " AND source = ?"
            params.append(source)
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                'id': row[0],
                'timestamp': row[1],
                'level': row[2],
                'event_type': row[3],
                'message': row[4],
                'source': row[5],
                'user_id': row[6],
                'session_id': row[7],
                'ip_address': row[8],
                'user_agent': row[9],
                'details': json.loads(row[10]) if row[10] else {},
                'correlation_id': row[11],
                'severity': row[12],
                'classification': row[13]
            })
        
        return logs

    def search_audits(self, start_time: datetime = None, end_time: datetime = None,
                     action: AuditAction = None, user_id: str = None,
                     result: str = None, limit: int = 1000) -> List[Dict]:
        """搜尋審計記錄"""
        cursor = self.db_conn.cursor()
        
        query = "SELECT * FROM audit_entries WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        if action:
            query += " AND action = ?"
            params.append(action.value)
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if result:
            query += " AND result = ?"
            params.append(result)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        audits = []
        for row in rows:
            audits.append({
                'id': row[0],
                'timestamp': row[1],
                'action': row[2],
                'resource': row[3],
                'user_id': row[4],
                'session_id': row[5],
                'ip_address': row[6],
                'user_agent': row[7],
                'result': row[8],
                'details': json.loads(row[9]) if row[9] else {},
                'risk_level': row[10],
                'compliance_tags': json.loads(row[11]) if row[11] else []
            })
        
        return audits

    def generate_compliance_report(self, start_date: datetime, end_date: datetime) -> Dict:
        """生成合規報告"""
        cursor = self.db_conn.cursor()
        
        # 統計審計事件
        cursor.execute('''
            SELECT action, result, COUNT(*) as count
            FROM audit_entries
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY action, result
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        audit_stats = {}
        for row in cursor.fetchall():
            action, result, count = row
            if action not in audit_stats:
                audit_stats[action] = {}
            audit_stats[action][result] = count
        
        # 統計安全事件
        cursor.execute('''
            SELECT event_type, level, COUNT(*) as count
            FROM log_entries
            WHERE timestamp BETWEEN ? AND ?
            AND event_type = 'SECURITY'
            GROUP BY event_type, level
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        security_stats = {}
        for row in cursor.fetchall():
            event_type, level, count = row
            if event_type not in security_stats:
                security_stats[event_type] = {}
            security_stats[event_type][level] = count
        
        # 統計用戶活動
        cursor.execute('''
            SELECT user_id, COUNT(*) as count
            FROM audit_entries
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY user_id
            ORDER BY count DESC
            LIMIT 10
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        user_stats = [{'user_id': row[0], 'activity_count': row[1]} for row in cursor.fetchall()]
        
        return {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'audit_statistics': audit_stats,
            'security_statistics': security_stats,
            'top_users': user_stats,
            'compliance_summary': {
                'total_audit_events': sum(sum(stats.values()) for stats in audit_stats.values()),
                'failed_attempts': sum(stats.get('FAILURE', 0) for stats in audit_stats.values()),
                'security_events': sum(sum(stats.values()) for stats in security_stats.values())
            }
        }

    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        cursor = self.db_conn.cursor()
        
        # 日誌統計
        cursor.execute('SELECT COUNT(*) FROM log_entries')
        total_logs = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM log_entries WHERE timestamp >= datetime("now", "-1 day")')
        daily_logs = cursor.fetchone()[0]
        
        # 審計統計
        cursor.execute('SELECT COUNT(*) FROM audit_entries')
        total_audits = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM audit_entries WHERE timestamp >= datetime("now", "-1 day")')
        daily_audits = cursor.fetchone()[0]
        
        # 佇列統計
        with self.queue_lock:
            log_queue_size = len(self.log_queue)
            audit_queue_size = len(self.audit_queue)
        
        return {
            'total_logs': total_logs,
            'daily_logs': daily_logs,
            'total_audits': total_audits,
            'daily_audits': daily_audits,
            'log_queue_size': log_queue_size,
            'audit_queue_size': audit_queue_size,
            'log_files_count': len(list(self.log_dir.glob("*.log*")))
        }

def main():
    """主程式"""
    config = {
        'log_dir': 'logs',
        'retention_days': 30
    }
    
    audit_logger = AuditLogger(config)
    
    # 測試日誌記錄
    audit_logger.log_event(
        level=LogLevel.INFO,
        event_type=EventType.SYSTEM,
        message="系統啟動",
        source="firewall_main",
        user_id="system",
        details={"version": "1.0.0", "pid": os.getpid()}
    )
    
    # 測試審計記錄
    audit_logger.audit_event(
        action=AuditAction.LOGIN,
        resource="firewall_dashboard",
        user_id="admin",
        session_id="sess_12345",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
        result="SUCCESS",
        details={"login_method": "password"},
        risk_level="LOW",
        compliance_tags=["SOX", "PCI-DSS"]
    )
    
    # 等待處理
    time.sleep(2)
    
    # 顯示統計
    stats = audit_logger.get_statistics()
    print(f"統計資訊: {stats}")
    
    # 搜尋日誌
    logs = audit_logger.search_logs(limit=10)
    print(f"最近日誌: {len(logs)} 條")
    
    # 搜尋審計
    audits = audit_logger.search_audits(limit=10)
    print(f"最近審計: {len(audits)} 條")

if __name__ == "__main__":
    main()

