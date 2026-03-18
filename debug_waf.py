#!/usr/bin/env python3
"""
WAF 調試腳本
"""

import asyncio
import aiohttp
import json

async def debug_waf():
    """調試 WAF 行為"""
    print("=== WAF 調試測試 ===")
    
    test_cases = [
        {"url": "http://localhost:8080/", "name": "正常請求"},
        {"url": "http://localhost:8080/admin", "name": "管理員路徑"},
        {"url": "http://localhost:8080/?id=1' OR '1'='1", "name": "SQL 注入"},
    ]
    
    async with aiohttp.ClientSession() as session:
        for case in test_cases:
            print(f"\n測試: {case['name']}")
            print(f"URL: {case['url']}")
            
            try:
                async with session.get(case['url'], timeout=aiohttp.ClientTimeout(total=10)) as response:
                    print(f"狀態碼: {response.status}")
                    print(f"響應標頭: {dict(response.headers)}")
                    
                    # 讀取響應內容
                    content = await response.text()
                    print(f"響應內容: {content[:200]}...")
                    
            except Exception as e:
                print(f"錯誤: {e}")

if __name__ == "__main__":
    asyncio.run(debug_waf())



