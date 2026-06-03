---
layout: post
title:  "Microsoft's Coreutils project brings Linux commands to Windows"
date:   2026-06-03 03:27:53 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Coreutils for Windows：Linux 命令行工具在 Windows 上的實現

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `NTFS Hardlinks`, `Rust`, `Cross-Platform`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Coreutils for Windows 專案使用 NTFS Hardlinks 來實現多個 Linux 命令行工具的功能。這些 Hardlinks 都指向同一個 `coreutils.exe` 可執行檔。然而，如果攻擊者可以創建一個具有相同名稱的可執行檔，並將其放在系統路徑中，則可能導致 LPE。
* **攻擊流程圖解**:
  1. 攻擊者創建一個具有相同名稱的可執行檔 (例如 `ls.exe`)。
  2. 攻擊者將該可執行檔放在系統路徑中 (例如 `C:\Windows\System32`）。
  3. 使用者執行 `ls` 命令，Windows 加載 `coreutils.exe` 並根據命令名稱決定要執行的工具。
  4. 如果攻擊者的可執行檔具有相同的名稱，則 Windows 會執行攻擊者的可執行檔而不是 `coreutils.exe`。
* **受影響元件**: Microsoft Coreutils for Windows (版本 1.0.0)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要具有系統管理員權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 創建一個具有相同名稱的可執行檔
    payload = "ls.exe"
    with open(payload, "wb") as f:
        f.write(b"evil payload")
    
    # 將可執行檔放在系統路徑中
    os.system(f"move {payload} C:\\Windows\\System32")
    
    ```
* **繞過技術**: 攻擊者可以使用 NTFS Hardlinks 來繞過系統的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `example.com` | `C:\Windows\System32\ls.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Coreutils_For_Windows {
        meta:
            description = "Detects Microsoft Coreutils for Windows"
            author = "Your Name"
        strings:
            $a = "coreutils.exe"
        condition:
            $a at 0
    }
    
    ```
* **緩解措施**: 更新 Microsoft Coreutils for Windows 至最新版本，並設定系統路徑中的可執行檔為唯讀。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NTFS Hardlinks**: NTFS Hardlinks 是 Windows 檔案系統中的連結機制。它允許多個檔案名稱指向同一個檔案。
* **Rust**: Rust 是一種程式設計語言，注重安全性和效率。
* **Cross-Platform**: Cross-Platform 指的是可以在多個平台上運行的軟體。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsofts-coreutils-project-brings-linux-commands-to-windows/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


