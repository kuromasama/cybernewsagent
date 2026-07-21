---
layout: post
title:  "Windows LegacyHive zero-day flaw gets free, unofficial patches"
date:   2026-07-21 08:14:03 +0000
categories: [security]
severity: high
---

# 🔥 解析 Windows LegacyHive 零日漏洞：利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Windows User Profile Service`, `Registry Hive`, `Code Execution`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LegacyHive 漏洞源於 Windows User Profile Service 中的 `registry hive` 處理機制。攻擊者可以利用這個漏洞在非管理員權限下修改其他用戶的 `registry hive`，從而實現本地權限提升。
* **攻擊流程圖解**:
  1. 攻擊者獲得非管理員權限的 Windows 系統存取權。
  2. 攻擊者利用 LegacyHive 漏洞修改其他用戶的 `registry hive`。
  3. 攻擊者在 `registry hive` 中添加惡意代碼或修改系統設定。
  4. 當管理員用戶登入系統時，惡意代碼被執行，實現本地權限提升。
* **受影響元件**: Windows 10 2004 或更新版本，Windows Server 2019 或更新版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 非管理員權限的 Windows 系統存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import winreg
    
    # 打開目標用戶的 registry hive
    hive = winreg.OpenKey(winreg.HKEY_USERS, r'S-1-5-21-<SID>', 0, winreg.KEY_ALL_ACCESS)
    
    # 添加惡意代碼或修改系統設定
    winreg.SetValueEx(hive, 'MaliciousKey', 0, winreg.REG_SZ, 'MaliciousValue')
    
    # 關閉 registry hive
    winreg.CloseKey(hive)
    
    ```
  *範例指令*: 使用 `curl` 或 `powershell` 執行惡意代碼。
* **繞過技術**: 可以利用 `Windows Defender` 的配置文件進行繞過。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `<hash>` | `<ip>` | `<domain>` | `<file_path>` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LegacyHive_Detection {
      meta:
        description = "Detects LegacyHive exploit"
        author = "Your Name"
      strings:
        $s1 = "S-1-5-21-<SID>"
        $s2 = "MaliciousKey"
      condition:
        all of them
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=windows_security EventID=4688 | search "S-1-5-21-<SID>" "MaliciousKey"
    
    ```
* **緩解措施**: 除了安裝官方修補程序外，還可以修改 `Windows User Profile Service` 的配置文件以限制非管理員用戶的權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Registry Hive**: 一種 Windows 的配置文件儲存機制，儲存用戶和系統的設定。
* **Local Privilege Escalation (LPE)**: 一種攻擊技術，利用系統漏洞或配置錯誤實現本地權限提升。
* **Windows User Profile Service**: 一種 Windows 服務，負責管理用戶配置文件和系統設定。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/windows-legacyhive-zero-day-flaw-gets-free-unofficial-patches/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


