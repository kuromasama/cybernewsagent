---
layout: post
title:  "Four OpenClaw Flaws Enable Data Theft, Privilege Escalation, and Persistence"
date:   2026-05-15 19:21:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OpenClaw 四大安全漏洞：從資料竊取到特權提升
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.6/6.3)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local Privilege Escalation)
> * **關鍵技術**: Time-of-Check/Time-of-Use (TOCTOU) 競爭危害、Shell Expansion Tokens、Improper Access Control

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OpenClaw 的 OpenShell 管理沙盒後端存在 TOCTOU 競爭危害，允許攻擊者繞過沙盒限制，導致資料竊取和特權提升。
* **攻擊流程圖解**:
  1. 攻擊者獲得代碼執行權限。
  2. 利用 CVE-2026-44113 和 CVE-2026-44115 獲取敏感資料。
  3. 利用 CVE-2026-44118 獲取 owner 級別控制權。
  4. 利用 CVE-2026-44112 設置後門和持久化控制。
* **受影響元件**: OpenClaw 版本 2026.4.22 之前。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得代碼執行權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建立一個惡意的 plugin
    plugin = {
        'name': 'malicious_plugin',
        'code': 'echo "Hello, World!" > /tmp/malicious_file'
    }
    
    # 發送請求到 OpenClaw 伺服器
    response = requests.post('https://openclaw-server.com/plugin', json=plugin)
    
    # 利用 CVE-2026-44113 和 CVE-2026-44115 獲取敏感資料
    sensitive_data = requests.get('https://openclaw-server.com/sensitive_data').text
    
    # 利用 CVE-2026-44118 獲取 owner 級別控制權
    owner_token = requests.post('https://openclaw-server.com/owner_token', json={'username': 'owner', 'password': 'password'}).json()['token']
    
    # 利用 CVE-2026-44112 設置後門和持久化控制
    backdoor = requests.post('https://openclaw-server.com/backdoor', json={'token': owner_token, 'code': 'echo "Hello, World!" > /tmp/backdoor_file'})
    
    ```
* **繞過技術**: 攻擊者可以使用 Shell Expansion Tokens 繞過 allowlist 驗證。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | openclaw-server.com | /tmp/malicious_file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OpenClaw_Malicious_Plugin {
        meta:
            description = "Detects malicious plugins in OpenClaw"
            author = "Your Name"
        strings:
            $plugin_name = "malicious_plugin"
            $plugin_code = "echo \"Hello, World!\" > /tmp/malicious_file"
        condition:
            $plugin_name and $plugin_code
    }
    
    ```
* **緩解措施**: 更新 OpenClaw 至版本 2026.4.22 或以上，設定 allowlist 驗證，監控系統日誌和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Time-of-Check/Time-of-Use (TOCTOU) 競爭危害**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Shell Expansion Tokens**: 一種 Shell 腳本語法，允許使用者定義變數和函數。
* **Improper Access Control**: 一種安全漏洞，允許攻擊者繞過存取控制機制，獲得未經授權的權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/four-openclaw-flaws-enable-data-theft.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


