# 藍隊 SOAR（Windows 被動監控）

## 功能
- 監控 Suricata EVE alert（Windows 上被動監控）
- 自動封鎖來源 IP（防火牆協同模組）
- 白名單、嚴重度門檻、TTL 可設定

## 設定
real_ultimate_defense_config.yaml：
```
blue_team_soar:
  enabled: true
  priority: 1
  config:
    sources:
      suricata_eve: "C:\\ProgramData\\Suricata\\logs\\eve.json"
      consume_sysmon: false
    policy:
      min_severity: 2
      whitelist: ["127.0.0.1"]
    actions:
      auto_block: true
      block_ttl_minutes: 60
```

## 啟動
- 跟著主系統啟動即可：會自動 tail EVE 檔。

## 驗證
- 觸發 Suricata alert（sev <= 2），應在 Windows 防火牆新增封鎖規則。




