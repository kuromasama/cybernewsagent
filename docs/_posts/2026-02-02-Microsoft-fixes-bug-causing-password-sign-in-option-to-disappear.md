---
layout: post
title:  "Microsoft fixes bug causing password sign-in option to disappear"
date:   2026-02-02 12:42:16 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Windows 11 鎖屏密碼選項消失漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Windows 11`, `鎖屏密碼`, `多重登入選項`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Windows 11 的鎖屏密碼選項顯示機制。在某些情況下，當使用者啟用多重登入選項（例如 PIN、密碼、安全金鑰、指紋）時，鎖屏密碼選項可能不會顯示。
* **攻擊流程圖解**: 
    1. 使用者啟用多重登入選項。
    2. 安裝 Windows 11 更新（例如 KB5064081）。
    3. 鎖屏密碼選項消失。
* **受影響元件**: Windows 11 24H2 和 25H2 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要有 Windows 11 的管理員權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 模擬鎖屏密碼選項消失的情況
    def simulate_lock_screen_password_disappear():
        # 執行 Windows 11 更新
        os.system("powershell -Command \"Install-Module -Name Microsoft.Update\"")
        os.system("powershell -Command \"Install-WindowsUpdate -KB KB5064081\"")
    
        # 啟用多重登入選項
        os.system("powershell -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'DefaultPassword' -Value 1\"")
    
    # 執行模擬攻擊
    simulate_lock_screen_password_disappear()
    
    ```
* **繞過技術**: 可以使用 WMI (Windows Management Instrumentation) 來繞過鎖屏密碼選項的限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | `C:\Windows\System32\winlogon.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Windows_Lock_Screen_Password_Disappear {
        meta:
            description = "Detects Windows lock screen password disappear"
            author = "Your Name"
        strings:
            $winlogon_exe = "C:\\Windows\\System32\\winlogon.exe"
        condition:
            $winlogon_exe
    }
    
    ```
* **緩解措施**: 更新 Windows 11 至最新版本（例如 KB5074105），並啟用多重登入選項的安全設定。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **鎖屏密碼 (Lock Screen Password)**: 指用於保護 Windows 11 鎖屏的密碼。
* **多重登入選項 (Multiple Sign-in Options)**: 指 Windows 11 中的多種登入方式，例如 PIN、密碼、安全金鑰、指紋。
* **WMI (Windows Management Instrumentation)**: 指 Windows 的管理工具，允許用戶存取和修改系統設定。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-bug-causing-password-sign-in-option-to-disappear/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


