#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""防火牆初始化驗證"""
from national_defense_firewall import NationalDefenseFirewall
fw = NationalDefenseFirewall()
a = fw.comprehensive_assessment()
print("防火牆:", a["firewall"])
print("能力覆蓋:", a["coverage"]["enabled"], "/", a["coverage"]["total"], "(", a["coverage"]["percentage"], "%)")
print("評級:", a["rating"]["grade"])
print("[OK] 防火牆初始化驗證完成")
