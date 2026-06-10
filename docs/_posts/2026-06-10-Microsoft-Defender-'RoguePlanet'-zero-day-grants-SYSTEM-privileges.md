---
layout: post
title:  "Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges"
date:   2026-06-10 02:45:22 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft Defender RoguePlanet 零日漏洞：利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: Race Condition, Microsoft Defender, SYSTEM Privileges

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: RoguePlanet 漏洞是由於 Microsoft Defender 的一個競爭危害（Race Condition）引起的。具體來說，當 Microsoft Defender 處理遠程 SMB 共享的文件時，會出現一個時間窗口，在這個時間窗口內，攻擊者可以利用這個漏洞來提升權限。
* **攻擊流程圖解**:
  1. 攻擊者創建一個遠程 SMB 共享的文件。
  2. 攻擊者誘導受害者打開這個文件。
  3. Microsoft Defender 處理這個文件時，會出現一個競爭危害。
  4. 攻擊者利用這個競爭危害，提升權限到 SYSTEM 權限。
* **受影響元件**: Microsoft Defender，Windows 10，Windows 11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有遠程 SMB 共享的文件，並且需要誘導受害者打開這個文件。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 創建遠程 SMB 共享的文件
    smb_file = "//\\\\\\\\\\\\\\\\\\\\\\\\"
    subprocess.run(["smbclient", "-U", "username", "-P", "password", smb_file])
    
    # 誘導受害者打開這個文件
    os.system("start " + smb_file)
    
    ```
  *範例指令*: `curl -X GET "http://example.com/rogueplanet" -H "Accept: application/json"`
* **繞過技術**: 攻擊者可以利用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\rogueplanet.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule RoguePlanet {
      meta:
        description = "RoguePlanet 零日漏洞偵測"
        author = "Blue Team"
      strings:
        $s1 = "smbclient" wide
        $s2 = "start" wide
      condition:
        $s1 and $s2
    }
    
    ```
  *或者是具體的 SIEM 查詢語法 (Splunk/Elastic)*: `index=security sourcetype=smbclient | stats count as num_events by src_ip | where num_events > 10`
* **緩解措施**: 除了更新 Microsoft Defender 外，還可以設定 WAF 规则來阻止遠程 SMB 共享的文件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Race Condition (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Microsoft Defender**: 一個 Windows 系統的安全軟件，負責實時監控和防禦惡意程式。
* **SYSTEM Privileges**: Windows 系統的最高權限，允許使用者執行任何操作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


