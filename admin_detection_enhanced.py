#!/usr/bin/env python3
"""
增強版管理員路徑檢測系統
提供更精確的管理員路徑識別和阻擋
"""

import re
import json
from typing import List, Dict, Any

class EnhancedAdminDetector:
    """增強版管理員路徑檢測器"""
    
    def __init__(self):
        # 管理員路徑模式（更全面的列表）
        self.admin_patterns = [
            # 常見管理員路徑
            r'/admin',
            r'/administrator', 
            r'/wp-admin',
            r'/phpmyadmin',
            r'/admin.php',
            r'/admin/',
            r'/administrator/',
            r'/wp-admin/',
            r'/phpmyadmin/',
            
            # 後台管理路徑
            r'/backend',
            r'/backend/',
            r'/management',
            r'/management/',
            r'/control',
            r'/control/',
            r'/dashboard',
            r'/dashboard/',
            
            # CMS 管理路徑
            r'/wp-admin',
            r'/wp-admin/',
            r'/wp-login.php',
            r'/wp-admin/admin.php',
            r'/admin/index.php',
            r'/administrator/index.php',
            
            # 資料庫管理
            r'/phpmyadmin',
            r'/phpmyadmin/',
            r'/pma',
            r'/pma/',
            r'/mysql',
            r'/mysql/',
            r'/dbadmin',
            r'/dbadmin/',
            
            # 系統管理
            r'/system',
            r'/system/',
            r'/sysadmin',
            r'/sysadmin/',
            r'/root',
            r'/root/',
            r'/superuser',
            r'/superuser/',
            
            # 文件管理
            r'/filemanager',
            r'/filemanager/',
            r'/files',
            r'/files/',
            r'/upload',
            r'/upload/',
            r'/uploads',
            r'/uploads/',
            
            # 配置管理
            r'/config',
            r'/config/',
            r'/settings',
            r'/settings/',
            r'/setup',
            r'/setup/',
            r'/install',
            r'/install/',
            
            # 日誌管理
            r'/logs',
            r'/logs/',
            r'/log',
            r'/log/',
            r'/audit',
            r'/audit/',
            
            # 測試和調試
            r'/test',
            r'/test/',
            r'/debug',
            r'/debug/',
            r'/dev',
            r'/dev/',
            r'/development',
            r'/development/',
            
            # 備份和維護
            r'/backup',
            r'/backup/',
            r'/maintenance',
            r'/maintenance/',
            r'/repair',
            r'/repair/',
            
            # 安全相關
            r'/security',
            r'/security/',
            r'/auth',
            r'/auth/',
            r'/login',
            r'/login/',
            r'/signin',
            r'/signin/',
            
            # 其他敏感路徑
            r'/api/admin',
            r'/api/admin/',
            r'/api/management',
            r'/api/management/',
            r'/admin/api',
            r'/admin/api/',
        ]
        
        # 編譯正則表達式以提高性能
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.admin_patterns]
        
        # 統計數據
        self.stats = {
            'total_checks': 0,
            'admin_paths_detected': 0,
            'blocked_requests': 0,
            'patterns_matched': {}
        }
    
    def check_path(self, path: str) -> Dict[str, Any]:
        """檢查路徑是否為管理員路徑"""
        self.stats['total_checks'] += 1
        
        # 檢查每個模式
        matched_patterns = []
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(path):
                pattern_name = self.admin_patterns[i]
                matched_patterns.append(pattern_name)
                self.stats['patterns_matched'][pattern_name] = self.stats['patterns_matched'].get(pattern_name, 0) + 1
        
        if matched_patterns:
            self.stats['admin_paths_detected'] += 1
            self.stats['blocked_requests'] += 1
            
            return {
                'is_admin_path': True,
                'matched_patterns': matched_patterns,
                'severity': 'HIGH',
                'action': 'BLOCK',
                'rule_id': 'RADMIN_ACCESS_ENHANCED'
            }
        else:
            return {
                'is_admin_path': False,
                'matched_patterns': [],
                'severity': 'LOW',
                'action': 'ALLOW',
                'rule_id': None
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """獲取統計數據"""
        return {
            'total_checks': self.stats['total_checks'],
            'admin_paths_detected': self.stats['admin_paths_detected'],
            'blocked_requests': self.stats['blocked_requests'],
            'detection_rate': (self.stats['admin_paths_detected'] / self.stats['total_checks'] * 100) if self.stats['total_checks'] > 0 else 0,
            'patterns_matched': self.stats['patterns_matched']
        }
    
    def add_custom_pattern(self, pattern: str):
        """添加自定義模式"""
        self.admin_patterns.append(pattern)
        self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
    
    def remove_pattern(self, pattern: str):
        """移除模式"""
        if pattern in self.admin_patterns:
            index = self.admin_patterns.index(pattern)
            self.admin_patterns.pop(index)
            self.compiled_patterns.pop(index)

def test_admin_detection():
    """測試管理員路徑檢測"""
    detector = EnhancedAdminDetector()
    
    # 測試路徑
    test_paths = [
        '/admin',
        '/administrator',
        '/wp-admin',
        '/phpmyadmin',
        '/admin/',
        '/wp-admin/',
        '/backend',
        '/management',
        '/dashboard',
        '/system',
        '/config',
        '/settings',
        '/logs',
        '/backup',
        '/security',
        '/api/admin',
        '/admin/api',
        '/normal/path',
        '/public/page',
        '/user/profile'
    ]
    
    print("測試增強版管理員路徑檢測...")
    print("=" * 50)
    
    results = []
    for path in test_paths:
        result = detector.check_path(path)
        results.append({
            'path': path,
            'is_admin': result['is_admin_path'],
            'matched_patterns': result['matched_patterns'],
            'action': result['action']
        })
        
        status = "BLOCK" if result['is_admin_path'] else "ALLOW"
        print(f"{path:<20} -> {status}")
    
    # 顯示統計
    stats = detector.get_stats()
    print("\n統計數據:")
    print(f"總檢查數: {stats['total_checks']}")
    print(f"檢測到管理員路徑: {stats['admin_paths_detected']}")
    print(f"阻擋請求數: {stats['blocked_requests']}")
    print(f"檢測率: {stats['detection_rate']:.1f}%")
    
    return results

if __name__ == "__main__":
    test_admin_detection()




