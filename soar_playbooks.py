#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOAR Playbooks - 安全編排自動化與響應
5 個核心 Playbook: isolate_host, block_ip, quarantine_file, revoke_credentials, restore_service
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import subprocess
import logging


class SOAREngine:
    """SOAR 編排引擎"""
    
    def __init__(self, playbooks_dir="./playbooks"):
        self.playbooks_dir = Path(playbooks_dir)
        self.playbooks_dir.mkdir(exist_ok=True)
        
        self.execution_log = []
        self.playbooks = self._load_playbooks()
        
        # 配置日誌
        logging.basicConfig(
            filename='soar_execution.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def _load_playbooks(self):
        """載入所有 Playbooks"""
        return {
            "isolate_host": self._playbook_isolate_host,
            "block_ip": self._playbook_block_ip,
            "quarantine_file": self._playbook_quarantine_file,
            "revoke_credentials": self._playbook_revoke_credentials,
            "restore_service": self._playbook_restore_service
        }
    
    def execute_playbook(self, playbook_name, parameters):
        """執行 Playbook"""
        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
        
        execution_record = {
            "run_id": run_id,
            "playbook": playbook_name,
            "parameters": parameters,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "RUNNING",
            "steps": [],
            "errors": []
        }
        
        logging.info(f"Starting playbook execution: {playbook_name} (Run ID: {run_id})")
        
        try:
            # 執行 Playbook
            if playbook_name not in self.playbooks:
                raise ValueError(f"Playbook '{playbook_name}' not found")
            
            playbook_func = self.playbooks[playbook_name]
            result = playbook_func(parameters, execution_record)
            
            execution_record['status'] = "SUCCESS"
            execution_record['result'] = result
            
        except Exception as e:
            execution_record['status'] = "FAILED"
            execution_record['errors'].append({
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            logging.error(f"Playbook execution failed: {playbook_name} - {str(e)}")
        
        finally:
            execution_record['completed_at'] = datetime.now(timezone.utc).isoformat()
            execution_record['duration'] = self._calculate_duration(
                execution_record['started_at'],
                execution_record['completed_at']
            )
            
            self.execution_log.append(execution_record)
            
            # 保存執行記錄
            self._save_execution_log(execution_record)
        
        return execution_record
    
    def _playbook_isolate_host(self, params, execution_record):
        """Playbook: 隔離主機"""
        steps = []
        
        hostname = params.get('hostname')
        ip_address = params.get('ip_address')
        reason = params.get('reason', 'Security incident')
        
        # Step 1: 驗證主機
        step1 = self._execute_step(
            "Verify Host",
            f"Verifying host {hostname} ({ip_address})",
            lambda: self._verify_host(hostname, ip_address)
        )
        steps.append(step1)
        
        # Step 2: 封鎖網路存取
        step2 = self._execute_step(
            "Block Network Access",
            f"Blocking network access for {ip_address}",
            lambda: self._block_network_access(ip_address)
        )
        steps.append(step2)
        
        # Step 3: 停止可疑進程
        step3 = self._execute_step(
            "Stop Suspicious Processes",
            f"Stopping suspicious processes on {hostname}",
            lambda: self._stop_suspicious_processes(hostname)
        )
        steps.append(step3)
        
        # Step 4: 收集證據
        step4 = self._execute_step(
            "Collect Evidence",
            f"Collecting forensic evidence from {hostname}",
            lambda: self._collect_host_evidence(hostname)
        )
        steps.append(step4)
        
        # Step 5: 通知 SOC
        step5 = self._execute_step(
            "Notify SOC",
            f"Sending notification to SOC team",
            lambda: self._notify_soc(f"Host {hostname} isolated due to: {reason}")
        )
        steps.append(step5)
        
        execution_record['steps'] = steps
        
        return {
            "isolated": True,
            "hostname": hostname,
            "ip_address": ip_address,
            "steps_completed": len([s for s in steps if s['status'] == 'SUCCESS']),
            "total_steps": len(steps)
        }
    
    def _playbook_block_ip(self, params, execution_record):
        """Playbook: 封鎖 IP"""
        steps = []
        
        ip_address = params.get('ip_address')
        reason = params.get('reason', 'Malicious activity')
        duration = params.get('duration', 3600)  # 預設 1 小時
        
        # Step 1: 驗證 IP
        step1 = self._execute_step(
            "Verify IP",
            f"Verifying IP {ip_address}",
            lambda: self._verify_ip(ip_address)
        )
        steps.append(step1)
        
        # Step 2: 添加防火牆規則
        step2 = self._execute_step(
            "Add Firewall Rule",
            f"Adding block rule for {ip_address}",
            lambda: self._add_firewall_rule(ip_address, "BLOCK")
        )
        steps.append(step2)
        
        # Step 3: 更新 WAF 黑名單
        step3 = self._execute_step(
            "Update WAF Blacklist",
            f"Adding {ip_address} to WAF blacklist",
            lambda: self._update_waf_blacklist(ip_address, "ADD")
        )
        steps.append(step3)
        
        # Step 4: 記錄到 SIEM
        step4 = self._execute_step(
            "Log to SIEM",
            f"Logging IP block event to SIEM",
            lambda: self._log_to_siem("IP_BLOCKED", {"ip": ip_address, "reason": reason})
        )
        steps.append(step4)
        
        # Step 5: 排程自動解封（如果有期限）
        if duration > 0:
            step5 = self._execute_step(
                "Schedule Unblock",
                f"Scheduling automatic unblock after {duration} seconds",
                lambda: self._schedule_unblock(ip_address, duration)
            )
            steps.append(step5)
        
        execution_record['steps'] = steps
        
        return {
            "blocked": True,
            "ip_address": ip_address,
            "duration": duration,
            "steps_completed": len([s for s in steps if s['status'] == 'SUCCESS'])
        }
    
    def _playbook_quarantine_file(self, params, execution_record):
        """Playbook: 隔離檔案"""
        steps = []
        
        file_path = params.get('file_path')
        file_hash = params.get('file_hash')
        hostname = params.get('hostname')
        
        # Step 1: 驗證檔案
        step1 = self._execute_step(
            "Verify File",
            f"Verifying file {file_path}",
            lambda: self._verify_file(file_path, file_hash)
        )
        steps.append(step1)
        
        # Step 2: 計算檔案雜湊
        step2 = self._execute_step(
            "Calculate Hash",
            f"Calculating SHA-256 hash",
            lambda: self._calculate_hash(file_path)
        )
        steps.append(step2)
        
        # Step 3: 移動到隔離區
        step3 = self._execute_step(
            "Move to Quarantine",
            f"Moving file to quarantine area",
            lambda: self._move_to_quarantine(file_path)
        )
        steps.append(step3)
        
        # Step 4: 送交沙箱分析
        step4 = self._execute_step(
            "Submit to Sandbox",
            f"Submitting file for malware analysis",
            lambda: self._submit_to_sandbox(file_hash)
        )
        steps.append(step4)
        
        # Step 5: 更新 IoC 資料庫
        step5 = self._execute_step(
            "Update IoC Database",
            f"Adding file hash to IoC database",
            lambda: self._update_ioc_database(file_hash, "MALICIOUS")
        )
        steps.append(step5)
        
        execution_record['steps'] = steps
        
        return {
            "quarantined": True,
            "file_path": file_path,
            "file_hash": file_hash,
            "quarantine_location": f"/quarantine/{file_hash}",
            "steps_completed": len([s for s in steps if s['status'] == 'SUCCESS'])
        }
    
    def _playbook_revoke_credentials(self, params, execution_record):
        """Playbook: 撤銷憑證"""
        steps = []
        
        username = params.get('username')
        credential_type = params.get('credential_type', 'PASSWORD')  # PASSWORD, TOKEN, CERTIFICATE
        reason = params.get('reason', 'Compromised credentials')
        
        # Step 1: 驗證用戶
        step1 = self._execute_step(
            "Verify User",
            f"Verifying user {username}",
            lambda: self._verify_user(username)
        )
        steps.append(step1)
        
        # Step 2: 終止所有 Session
        step2 = self._execute_step(
            "Terminate Sessions",
            f"Terminating all active sessions for {username}",
            lambda: self._terminate_sessions(username)
        )
        steps.append(step2)
        
        # Step 3: 撤銷憑證
        step3 = self._execute_step(
            "Revoke Credentials",
            f"Revoking {credential_type} for {username}",
            lambda: self._revoke_credentials(username, credential_type)
        )
        steps.append(step3)
        
        # Step 4: 生成臨時密碼
        step4 = self._execute_step(
            "Generate Temporary Password",
            f"Generating temporary password for {username}",
            lambda: self._generate_temp_password(username)
        )
        steps.append(step4)
        
        # Step 5: 通知用戶
        step5 = self._execute_step(
            "Notify User",
            f"Sending notification to {username}",
            lambda: self._notify_user(username, reason)
        )
        steps.append(step5)
        
        execution_record['steps'] = steps
        
        return {
            "revoked": True,
            "username": username,
            "credential_type": credential_type,
            "steps_completed": len([s for s in steps if s['status'] == 'SUCCESS'])
        }
    
    def _playbook_restore_service(self, params, execution_record):
        """Playbook: 恢復服務"""
        steps = []
        
        service_name = params.get('service_name')
        restore_method = params.get('restore_method', 'RESTART')  # RESTART, BACKUP, FAILOVER
        
        # Step 1: 檢查服務狀態
        step1 = self._execute_step(
            "Check Service Status",
            f"Checking status of {service_name}",
            lambda: self._check_service_status(service_name)
        )
        steps.append(step1)
        
        # Step 2: 停止受損服務
        step2 = self._execute_step(
            "Stop Service",
            f"Stopping {service_name}",
            lambda: self._stop_service(service_name)
        )
        steps.append(step2)
        
        # Step 3: 清理惡意內容
        step3 = self._execute_step(
            "Clean Malicious Content",
            f"Removing malicious content from {service_name}",
            lambda: self._clean_service(service_name)
        )
        steps.append(step3)
        
        # Step 4: 恢復服務
        if restore_method == 'RESTART':
            step4 = self._execute_step(
                "Restart Service",
                f"Restarting {service_name}",
                lambda: self._restart_service(service_name)
            )
        elif restore_method == 'BACKUP':
            step4 = self._execute_step(
                "Restore from Backup",
                f"Restoring {service_name} from backup",
                lambda: self._restore_from_backup(service_name)
            )
        else:  # FAILOVER
            step4 = self._execute_step(
                "Failover to Backup",
                f"Switching to backup instance of {service_name}",
                lambda: self._failover_service(service_name)
            )
        steps.append(step4)
        
        # Step 5: 驗證服務可用性
        step5 = self._execute_step(
            "Verify Service Availability",
            f"Verifying {service_name} is operational",
            lambda: self._verify_service_availability(service_name)
        )
        steps.append(step5)
        
        execution_record['steps'] = steps
        
        return {
            "restored": True,
            "service_name": service_name,
            "restore_method": restore_method,
            "steps_completed": len([s for s in steps if s['status'] == 'SUCCESS'])
        }
    
    def _execute_step(self, step_name, description, action_func):
        """執行單一步驟"""
        step = {
            "step_name": step_name,
            "description": description,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "RUNNING"
        }
        
        try:
            result = action_func()
            step['status'] = "SUCCESS"
            step['result'] = result
            logging.info(f"Step completed: {step_name} - SUCCESS")
            
        except Exception as e:
            step['status'] = "FAILED"
            step['error'] = str(e)
            logging.error(f"Step failed: {step_name} - {str(e)}")
        
        finally:
            step['completed_at'] = datetime.now(timezone.utc).isoformat()
            step['duration'] = self._calculate_duration(
                step['started_at'],
                step['completed_at']
            )
        
        return step
    
    # ==================== 模擬動作函數 ====================
    
    def _verify_host(self, hostname, ip_address):
        """驗證主機"""
        time.sleep(0.1)  # 模擬執行時間
        return {"verified": True, "hostname": hostname, "ip": ip_address}
    
    def _block_network_access(self, ip_address):
        """封鎖網路存取"""
        time.sleep(0.2)
        # 在實際環境中，這裡會呼叫防火牆 API
        return {"blocked": True, "ip": ip_address, "rule_id": f"FW-{uuid.uuid4().hex[:8]}"}
    
    def _stop_suspicious_processes(self, hostname):
        """停止可疑進程"""
        time.sleep(0.3)
        # 實際環境會透過 EDR API 停止進程
        return {"stopped_processes": ["malware.exe", "suspicious_script.py"], "count": 2}
    
    def _collect_host_evidence(self, hostname):
        """收集主機證據"""
        time.sleep(0.5)
        return {
            "memory_dump": f"/evidence/{hostname}_memory.raw",
            "disk_snapshot": f"/evidence/{hostname}_disk.img",
            "event_logs": f"/evidence/{hostname}_logs.json"
        }
    
    def _notify_soc(self, message):
        """通知 SOC 團隊"""
        time.sleep(0.1)
        # 實際環境會發送郵件/Slack/Teams 通知
        logging.info(f"SOC Notification: {message}")
        return {"notified": True, "message": message}
    
    def _verify_ip(self, ip_address):
        """驗證 IP"""
        time.sleep(0.1)
        return {"valid": True, "ip": ip_address}
    
    def _add_firewall_rule(self, ip_address, action):
        """添加防火牆規則"""
        time.sleep(0.2)
        return {"rule_added": True, "ip": ip_address, "action": action}
    
    def _update_waf_blacklist(self, ip_address, operation):
        """更新 WAF 黑名單"""
        time.sleep(0.1)
        # 實際會更新 secure_web_system.py 的 blocked_ips
        return {"updated": True, "ip": ip_address, "operation": operation}
    
    def _log_to_siem(self, event_type, data):
        """記錄到 SIEM"""
        time.sleep(0.1)
        return {"logged": True, "event_type": event_type}
    
    def _schedule_unblock(self, ip_address, duration):
        """排程自動解封"""
        time.sleep(0.1)
        unblock_time = datetime.now(timezone.utc).timestamp() + duration
        return {"scheduled": True, "unblock_at": unblock_time}
    
    def _verify_file(self, file_path, file_hash):
        """驗證檔案"""
        time.sleep(0.1)
        return {"verified": True, "file": file_path, "hash": file_hash}
    
    def _calculate_hash(self, file_path):
        """計算檔案雜湊"""
        time.sleep(0.2)
        return {"sha256": f"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    
    def _move_to_quarantine(self, file_path):
        """移動到隔離區"""
        time.sleep(0.3)
        return {"moved": True, "quarantine_path": f"/quarantine/{Path(file_path).name}"}
    
    def _submit_to_sandbox(self, file_hash):
        """送交沙箱"""
        time.sleep(0.2)
        return {"submitted": True, "sandbox_id": f"SAND-{uuid.uuid4().hex[:8]}"}
    
    def _update_ioc_database(self, file_hash, classification):
        """更新 IoC 資料庫"""
        time.sleep(0.1)
        return {"updated": True, "hash": file_hash, "classification": classification}
    
    def _verify_user(self, username):
        """驗證用戶"""
        time.sleep(0.1)
        return {"verified": True, "username": username}
    
    def _terminate_sessions(self, username):
        """終止 Sessions"""
        time.sleep(0.2)
        return {"terminated": True, "session_count": 3}
    
    def _revoke_credentials(self, username, credential_type):
        """撤銷憑證"""
        time.sleep(0.2)
        return {"revoked": True, "username": username, "type": credential_type}
    
    def _generate_temp_password(self, username):
        """生成臨時密碼"""
        import secrets
        temp_password = secrets.token_urlsafe(16)
        return {"generated": True, "temp_password": temp_password}
    
    def _notify_user(self, username, reason):
        """通知用戶"""
        time.sleep(0.1)
        return {"notified": True, "username": username}
    
    def _check_service_status(self, service_name):
        """檢查服務狀態"""
        time.sleep(0.1)
        return {"status": "DOWN", "service": service_name}
    
    def _stop_service(self, service_name):
        """停止服務"""
        time.sleep(0.2)
        return {"stopped": True, "service": service_name}
    
    def _clean_service(self, service_name):
        """清理服務"""
        time.sleep(0.5)
        return {"cleaned": True, "removed_files": 5}
    
    def _restart_service(self, service_name):
        """重啟服務"""
        time.sleep(0.3)
        return {"restarted": True, "service": service_name}
    
    def _restore_from_backup(self, service_name):
        """從備份恢復"""
        time.sleep(1.0)
        return {"restored": True, "backup_timestamp": "2025-10-11T00:00:00Z"}
    
    def _failover_service(self, service_name):
        """服務容錯切換"""
        time.sleep(0.5)
        return {"failover": True, "new_instance": f"{service_name}-backup-1"}
    
    def _verify_service_availability(self, service_name):
        """驗證服務可用性"""
        time.sleep(0.2)
        return {"available": True, "response_time_ms": 45}
    
    def _calculate_duration(self, start_time, end_time):
        """計算持續時間"""
        from datetime import datetime
        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)
        duration = (end - start).total_seconds()
        return f"{duration:.3f}s"
    
    def _save_execution_log(self, execution_record):
        """保存執行記錄"""
        log_dir = Path("./playbook_logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"{execution_record['run_id']}.json"
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(execution_record, f, indent=2, ensure_ascii=False)
    
    def get_execution_history(self, limit=10):
        """獲取執行歷史"""
        return self.execution_log[-limit:]
    
    def generate_playbook_report(self):
        """生成 Playbook 執行報告"""
        total_runs = len(self.execution_log)
        successful_runs = len([r for r in self.execution_log if r['status'] == 'SUCCESS'])
        failed_runs = len([r for r in self.execution_log if r['status'] == 'FAILED'])
        
        # 按 Playbook 統計
        by_playbook = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        for record in self.execution_log:
            playbook = record['playbook']
            by_playbook[playbook]['total'] += 1
            if record['status'] == 'SUCCESS':
                by_playbook[playbook]['success'] += 1
            else:
                by_playbook[playbook]['failed'] += 1
        
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_executions": total_runs,
                "successful": successful_runs,
                "failed": failed_runs,
                "success_rate": successful_runs / total_runs * 100 if total_runs > 0 else 0
            },
            "by_playbook": dict(by_playbook),
            "recent_executions": self.get_execution_history(10)
        }
        
        # 保存報告
        with open('soar_playbook_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report


# 使用範例與測試
if __name__ == '__main__':
    print("=" * 60)
    print("SOAR Playbooks 自動化響應系統 - 示範")
    print("=" * 60)
    
    # 初始化
    soar = SOAREngine()
    
    # 1. 執行 isolate_host
    print("\n[1/5] 執行 Playbook: Isolate Host")
    result1 = soar.execute_playbook("isolate_host", {
        "hostname": "workstation-42",
        "ip_address": "192.168.1.100",
        "reason": "Detected malware activity"
    })
    print(f"  Run ID: {result1['run_id']}")
    print(f"  Status: {result1['status']}")
    print(f"  Steps: {len([s for s in result1['steps'] if s['status'] == 'SUCCESS'])}/{len(result1['steps'])} 成功")
    print(f"  Duration: {result1['duration']}")
    
    # 2. 執行 block_ip
    print("\n[2/5] 執行 Playbook: Block IP")
    result2 = soar.execute_playbook("block_ip", {
        "ip_address": "203.0.113.100",
        "reason": "DDoS attack source",
        "duration": 3600
    })
    print(f"  Run ID: {result2['run_id']}")
    print(f"  Status: {result2['status']}")
    print(f"  Duration: {result2['duration']}")
    
    # 3. 執行 quarantine_file
    print("\n[3/5] 執行 Playbook: Quarantine File")
    result3 = soar.execute_playbook("quarantine_file", {
        "file_path": "/tmp/malware.exe",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "hostname": "workstation-42"
    })
    print(f"  Run ID: {result3['run_id']}")
    print(f"  Status: {result3['status']}")
    print(f"  Duration: {result3['duration']}")
    
    # 4. 執行 revoke_credentials
    print("\n[4/5] 執行 Playbook: Revoke Credentials")
    result4 = soar.execute_playbook("revoke_credentials", {
        "username": "john.doe",
        "credential_type": "PASSWORD",
        "reason": "Suspected credential theft"
    })
    print(f"  Run ID: {result4['run_id']}")
    print(f"  Status: {result4['status']}")
    print(f"  Duration: {result4['duration']}")
    
    # 5. 執行 restore_service
    print("\n[5/5] 執行 Playbook: Restore Service")
    result5 = soar.execute_playbook("restore_service", {
        "service_name": "web_application",
        "restore_method": "RESTART"
    })
    print(f"  Run ID: {result5['run_id']}")
    print(f"  Status: {result5['status']}")
    print(f"  Duration: {result5['duration']}")
    
    # 生成報告
    print("\n[報告] 生成 Playbook 執行報告...")
    report = soar.generate_playbook_report()
    
    print("\n" + "=" * 60)
    print("SOAR Playbooks 執行摘要")
    print("=" * 60)
    print(f"總執行次數: {report['summary']['total_executions']}")
    print(f"成功次數: {report['summary']['successful']}")
    print(f"失敗次數: {report['summary']['failed']}")
    print(f"成功率: {report['summary']['success_rate']:.1f}%")
    
    print("\n各 Playbook 統計:")
    for playbook, stats in report['by_playbook'].items():
        print(f"  {playbook}:")
        print(f"    總計: {stats['total']}, 成功: {stats['success']}, 失敗: {stats['failed']}")
    
    print(f"\n詳細記錄已保存到: ./playbook_logs/")

