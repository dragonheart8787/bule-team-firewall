#!/usr/bin/env python3
"""
企業級系統部署和測試腳本 - 完整版本
整合所有修復：WAF 代理連線、實戰級壓測、HA 故障演練、規則治理、安全基線、驗收標準
"""

import asyncio
import subprocess
import time
import json
import os
import sys
import argparse
from datetime import datetime
import threading
import signal

class EnterpriseSystemDeployer:
    """企業級系統部署器"""
    
    def __init__(self):
        self.services = {}
        self.test_results = {}
        self.deployment_log = []
        
    def log(self, message: str, level: str = "INFO"):
        """記錄日誌"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        self.deployment_log.append(log_entry)
    
    def run_command(self, command: str, check: bool = True) -> subprocess.CompletedProcess:
        """執行命令"""
        self.log(f"執行命令: {command}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=check,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'  # 避免外部程式輸出造成的 UnicodeDecodeError
            )
            if result.stdout:
                self.log(f"輸出: {result.stdout.strip()}")
            return result
        except subprocess.CalledProcessError as e:
            self.log(f"命令執行失敗: {e}", "ERROR")
            if e.stderr:
                self.log(f"錯誤: {e.stderr.strip()}", "ERROR")
            raise
    
    def check_dependencies(self):
        """檢查依賴"""
        self.log("檢查系統依賴...")
        
        # 檢查 Python 版本
        python_version = sys.version_info
        if python_version < (3, 8):
            raise Exception("需要 Python 3.8 或更高版本")
        self.log(f"Python 版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        # 檢查必要的 Python 包
        required_packages = [
            'aiohttp', 'cryptography', 'psutil', 'matplotlib', 
            'pandas', 'numpy', 'requests'
        ]
        
        for package in required_packages:
            try:
                __import__(package)
                self.log(f"[OK] {package} 已安裝")
            except ImportError:
                self.log(f"[FAIL] {package} 未安裝，正在安裝...", "WARN")
                self.run_command(f"pip install {package}")
        
        # 檢查 Docker
        try:
            result = self.run_command("docker --version", check=False)
            if result.returncode == 0:
                self.log("[OK] Docker 已安裝")
            else:
                self.log("[WARN]  Docker 未安裝或未運行", "WARN")
        except:
            self.log("[WARN]  Docker 未安裝或未運行", "WARN")
        
        self.log("依賴檢查完成")
    
    def setup_environment(self):
        """設置環境"""
        self.log("設置環境變數...")
        
        # 設置環境變數
        env_vars = {
            'BACKEND_HOST': 'localhost',
            'BACKEND_PORT': '5000',
            'PROXY_PORT': '8080',
            'SIEM_PORT': '8001',
            'SSL_KEY_PASSWORD': 'enterprise_ssl_password_2024',
            'WAF_API_KEY': 'enterprise_waf_api_key_2024',
            'SIEM_API_KEY': 'enterprise_siem_api_key_2024',
            'MASTER_ENCRYPTION_KEY': 'enterprise_master_key_2024'
        }
        
        for key, value in env_vars.items():
            os.environ[key] = value
            self.log(f"設置 {key} = {value}")
        
        self.log("環境設置完成")
    
    def install_dependencies(self):
        """安裝依賴"""
        self.log("安裝 Python 依賴...")
        
        # 創建 requirements.txt
        requirements = [
            "aiohttp>=3.8.0",
            "cryptography>=3.4.8",
            "psutil>=5.8.0",
            "matplotlib>=3.5.0",
            "pandas>=1.3.0",
            "numpy>=1.21.0",
            "requests>=2.25.0",
            "fastapi>=0.68.0",
            "uvicorn>=0.15.0",
            "flask>=2.0.0"
        ]
        
        with open('requirements.txt', 'w') as f:
            f.write('\n'.join(requirements))
        
        self.run_command("pip install -r requirements.txt")
        self.log("依賴安裝完成")
    
    def generate_ssl_certificates(self):
        """生成 SSL 憑證"""
        self.log("生成 SSL 憑證...")
        
        try:
            # 運行 SSL 憑證生成腳本
            self.run_command("python create_ssl_cert.py")
            self.log("[OK] SSL 憑證生成成功")
        except Exception as e:
            self.log(f"SSL 憑證生成失敗: {e}", "ERROR")
            raise
    
    def start_services(self):
        """啟動服務"""
        self.log("啟動企業級服務...")
        
        # 啟動目標應用
        self.log("啟動目標應用...")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        target_app_process = subprocess.Popen(
            [sys.executable, "target_app.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            env=env
        )
        self.services['target_app'] = target_app_process
        time.sleep(2)
        
        # 啟動 SIEM 引擎
        self.log("啟動 SIEM 引擎...")
        siem_process = subprocess.Popen(
            [sys.executable, "siem_dashboards.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            env=env
        )
        self.services['siem_engine'] = siem_process
        time.sleep(3)
        
        # 啟動 WAF 代理
        self.log("啟動 WAF 代理...")
        waf_process = subprocess.Popen(
            [sys.executable, "waf_proxy_enterprise_fixed.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            env=env
        )
        self.services['waf_proxy'] = waf_process
        time.sleep(3)
        
        self.log("所有服務已啟動")
    
    def _wait_for_service(self, name: str, url: str, timeout_seconds: int = 45, interval: float = 1.5) -> bool:
        """輪詢等待單一服務健康就緒"""
        import requests
        start = time.time()
        while time.time() - start < timeout_seconds:
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code == 200 and resp.json().get('status') == 'ok':
                    self.log(f"[OK] {name} 健康")
                    return True
            except Exception as e:
                pass
            time.sleep(interval)
        self.log(f"[FAIL] {name} 無法在 {timeout_seconds}s 內通過健康檢查", "ERROR")
        return False

    def check_services_health(self):
        """檢查服務健康狀態"""
        self.log("檢查服務健康狀態...")
        services = [
            ("target_app", "http://localhost:5000/healthz", 20),
            ("siem_engine", "http://localhost:8001/healthz", 60),  # SIEM 可能較慢，延長等待
            ("waf_proxy", "http://localhost:8080/healthz", 30)
        ]
        results = [self._wait_for_service(name, url, timeout) for name, url, timeout in services]
        all_healthy = all(results)
        self.log("[OK] 所有服務健康" if all_healthy else "[FAIL] 部分服務不健康", "INFO" if all_healthy else "ERROR")
        return all_healthy
    
    def run_enterprise_tests(self):
        """運行企業級測試"""
        self.log("開始企業級測試...")
        
        # 測試 1: 實戰級壓測
        self.log("執行實戰級壓測...")
        try:
            result = self.run_command(
                "python enterprise_load_test_advanced.py --users 100 --duration 60 --attacks --https --rules-ab"
            )
            self.test_results['load_test'] = "PASSED"
            self.log("[OK] 實戰級壓測通過")
        except Exception as e:
            self.test_results['load_test'] = "FAILED"
            self.log(f"[FAIL] 實戰級壓測失敗: {e}", "ERROR")
        
        # 測試 2: HA 故障演練
        self.log("執行 HA 故障演練...")
        try:
            result = self.run_command(
                "python ha_chaos_test_advanced.py"
            )
            self.test_results['chaos_test'] = "PASSED"
            self.log("[OK] HA 故障演練通過")
        except Exception as e:
            self.test_results['chaos_test'] = "FAILED"
            self.log(f"[FAIL] HA 故障演練失敗: {e}", "ERROR")
        
        # 測試 3: 規則治理
        self.log("執行規則治理測試...")
        try:
            result = self.run_command(
                "python rule_governance_advanced.py"
            )
            self.test_results['governance_test'] = "PASSED"
            self.log("[OK] 規則治理測試通過")
        except Exception as e:
            self.test_results['governance_test'] = "FAILED"
            self.log(f"[FAIL] 規則治理測試失敗: {e}", "ERROR")
        
        # 測試 4: 安全基線
        self.log("執行安全基線測試...")
        try:
            result = self.run_command(
                "python security_baseline_advanced.py --action audit"
            )
            self.test_results['security_baseline'] = "PASSED"
            self.log("[OK] 安全基線測試通過")
        except Exception as e:
            self.test_results['security_baseline'] = "FAILED"
            self.log(f"[FAIL] 安全基線測試失敗: {e}", "ERROR")
        
        # 測試 5: 驗收標準
        self.log("執行驗收標準測試...")
        try:
            result = self.run_command(
                "python enterprise_validation_criteria.py"
            )
            self.test_results['validation_criteria'] = "PASSED"
            self.log("[OK] 驗收標準測試通過")
        except Exception as e:
            self.test_results['validation_criteria'] = "FAILED"
            self.log(f"[FAIL] 驗收標準測試失敗: {e}", "ERROR")
        
        self.log("企業級測試完成")
    
    def generate_deployment_report(self):
        """生成部署報告"""
        self.log("生成部署報告...")
        
        # 統計測試結果
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result == "PASSED")
        failed_tests = total_tests - passed_tests
        
        report = {
            "deployment_timestamp": datetime.now().isoformat(),
            "deployment_log": self.deployment_log,
            "test_results": self.test_results,
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            "services": list(self.services.keys()),
            "recommendations": self._generate_recommendations()
        }
        
        # 保存報告
        report_file = f"enterprise_deployment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.log(f"部署報告已保存到: {report_file}")
        
        # 顯示摘要
        print(f"\n{'='*80}")
        print("企業級系統部署摘要")
        print(f"{'='*80}")
        print(f"部署時間: {datetime.now()}")
        print(f"總測試數: {total_tests}")
        print(f"通過測試: {passed_tests}")
        print(f"失敗測試: {failed_tests}")
        print(f"成功率: {report['summary']['success_rate']:.1f}%")
        print()
        
        print("測試結果:")
        for test_name, result in self.test_results.items():
            status = "[OK] 通過" if result == "PASSED" else "[FAIL] 失敗"
            print(f"  {test_name}: {status}")
        
        print()
        if passed_tests == total_tests:
            print("🎉 恭喜！所有企業級測試通過，系統已準備就緒！")
        else:
            print(f"[WARN]  有 {failed_tests} 個測試失敗，請檢查並修復問題")
        
        return report
    
    def _generate_recommendations(self):
        """生成建議"""
        recommendations = []
        
        if self.test_results.get('load_test') == 'FAILED':
            recommendations.append("檢查系統效能配置，考慮增加資源或優化規則")
        
        if self.test_results.get('chaos_test') == 'FAILED':
            recommendations.append("檢查高可用性配置，確保故障轉移機制正常")
        
        if self.test_results.get('governance_test') == 'FAILED':
            recommendations.append("檢查規則治理流程，確保審批和回滾機制完善")
        
        if self.test_results.get('security_baseline') == 'FAILED':
            recommendations.append("檢查安全基線配置，確保憑證和機密管理正確")
        
        if self.test_results.get('validation_criteria') == 'FAILED':
            recommendations.append("檢查驗收標準，確保所有指標符合企業級要求")
        
        if not recommendations:
            recommendations.append("系統運行良好，建議定期進行安全審計和效能監控")
        
        return recommendations
    
    def cleanup(self):
        """清理資源"""
        self.log("清理資源...")
        
        for service_name, process in self.services.items():
            try:
                process.terminate()
                process.wait(timeout=5)
                self.log(f"[OK] {service_name} 已停止")
            except:
                try:
                    process.kill()
                    self.log(f"[OK] {service_name} 已強制停止")
                except:
                    self.log(f"[WARN]  {service_name} 停止失敗", "WARN")
        
        self.log("資源清理完成")
    
    def deploy(self):
        """執行完整部署"""
        try:
            self.log("開始企業級系統部署")
            print("=" * 80)
            
            # 步驟 1: 檢查依賴
            self.check_dependencies()
            
            # 步驟 2: 設置環境
            self.setup_environment()
            
            # 步驟 3: 安裝依賴
            self.install_dependencies()
            
            # 步驟 4: 生成 SSL 憑證
            self.generate_ssl_certificates()
            
            # 步驟 5: 啟動服務
            self.start_services()
            
            # 步驟 6: 檢查服務健康
            if not self.check_services_health():
                raise Exception("服務健康檢查失敗")
            
            # 步驟 7: 運行企業級測試
            self.run_enterprise_tests()
            
            # 步驟 8: 生成部署報告
            report = self.generate_deployment_report()
            
            self.log("企業級系統部署完成")
            return report
            
        except Exception as e:
            self.log(f"部署失敗: {e}", "ERROR")
            raise
        finally:
            # 清理資源
            self.cleanup()

def signal_handler(signum, frame):
    """信號處理器"""
    print("\n收到中斷信號，正在清理資源...")
    sys.exit(0)

def main():
    """主函數"""
    parser = argparse.ArgumentParser(description='企業級系統部署工具')
    parser.add_argument('--skip-tests', action='store_true', help='跳過測試')
    parser.add_argument('--test-only', action='store_true', help='只運行測試')
    parser.add_argument('--cleanup', action='store_true', help='只清理資源')
    
    args = parser.parse_args()
    
    # 設置信號處理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 創建部署器
    deployer = EnterpriseSystemDeployer()
    
    try:
        if args.cleanup:
            deployer.cleanup()
            return
        
        if args.test_only:
            deployer.setup_environment()
            deployer.start_services()
            if deployer.check_services_health():
                deployer.run_enterprise_tests()
                deployer.generate_deployment_report()
            deployer.cleanup()
            return
        
        if args.skip_tests:
            deployer.check_dependencies()
            deployer.setup_environment()
            deployer.install_dependencies()
            deployer.generate_ssl_certificates()
            deployer.start_services()
            deployer.check_services_health()
            deployer.cleanup()
            return
        
        # 完整部署
        deployer.deploy()
        
    except KeyboardInterrupt:
        print("\n部署被用戶中斷")
        deployer.cleanup()
    except Exception as e:
        print(f"部署失敗: {e}")
        deployer.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()
