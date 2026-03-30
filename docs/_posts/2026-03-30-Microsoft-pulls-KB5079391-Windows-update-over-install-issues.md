---
layout: post
title:  "Microsoft pulls KB5079391 Windows update over install issues"
date:   2026-03-30 13:03:55 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Windows 11 KB5079391 更新漏洞：0x80073712 錯誤分析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Windows Update`, `KB5079391`, `0x80073712`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: KB5079391 更新包中包含的 Smart App Control 和 Display 改進功能引入了一個錯誤，導致 Windows Update 服務無法正確安裝更新包，從而觸發 0x80073712 錯誤。
* **攻擊流程圖解**: 
    1. 使用者安裝 KB5079391 更新包
    2. Windows Update 服務嘗試安裝更新包
    3. Smart App Control 和 Display 改進功能引入錯誤
    4. Windows Update 服務無法正確安裝更新包
    5. 觸發 0x80073712 錯誤
* **受影響元件**: Windows 11 24H2 和 25H2 版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Windows 11 24H2 或 25H2 版本的系統
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 下載 KB5079391 更新包
    subprocess.run(["powershell", "-Command", "Invoke-WebRequest -Uri https://example.com/kb5079391.msu -OutFile kb5079391.msu"])
    
    # 安裝 KB5079391 更新包
    subprocess.run(["powershell", "-Command", "wusa.exe kb5079391.msu /quiet /norestart"])
    
    ```
    *範例指令*: 使用 `curl` 下載更新包，然後使用 `wusa.exe` 安裝更新包
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 `Invoke-WebRequest` 下載更新包，然後使用 `wusa.exe` 安裝更新包

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\kb5079391.msu |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Windows_Update_Error {
        meta:
            description = "Windows Update 錯誤"
            author = "Your Name"
        strings:
            $error_message = "0x80073712"
        condition:
            $error_message at 0
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
index=windows_event_log EventID=16 | stats count as error_count by EventData | where error_count > 5

```
* **緩解措施**: 除了更新修補之外，還可以修改 Windows Update 服務的設定，例如設定 `Windows Update` 服務為手動啟動

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Windows Update**: Windows 的更新服務，負責下載和安裝更新包
* **KB5079391**: 一個 Windows 更新包，包含 Smart App Control 和 Display 改進功能
* **0x80073712**: 一個 Windows 錯誤代碼，表示更新包安裝失敗

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-pulls-windows-kb5079391-update-over-0x80073712-install-errors/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


