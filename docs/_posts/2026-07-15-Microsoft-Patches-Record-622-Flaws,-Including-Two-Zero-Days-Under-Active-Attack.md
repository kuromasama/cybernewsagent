---
layout: post
title:  "Microsoft Patches Record 622 Flaws, Including Two Zero-Days Under Active Attack"
date:   2026-07-15 01:46:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft Patch Tuesday：CVE-2026-56164 和 CVE-2026-56155 利用與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 8.8)
> * **受駭指標**: Elevation of Privilege (LPE)
> * **關鍵技術**: SharePoint Server, Active Directory Federation Services, AMSI

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CVE-2026-56164 是一個存在於 SharePoint Server 的權限提升漏洞，允許未經驗證的攻擊者在網路上提升權限。CVE-2026-56155 是一個存在於 Active Directory Federation Services 的權限提升漏洞，允許已經驗證的攻擊者在本地提升權限。
* **攻擊流程圖解**:
    + User Input -> SharePoint Server -> Authentication Bypass -> Elevation of Privilege
    + User Input -> Active Directory Federation Services -> Weak Access Control -> Elevation of Privilege
* **受影響元件**: SharePoint Server 2016 和 2019，Active Directory Federation Services

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路存取，SharePoint Server 或 Active Directory Federation Services 的存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # SharePoint Server Exploit
    url = "https://example.com/_api/contextinfo"
    headers = {"Accept": "application/json;odata=verbose"}
    response = requests.post(url, headers=headers)
    
    # Active Directory Federation Services Exploit
    url = "https://example.com/adfs/ls/"
    headers = {"Accept": "application/json"}
    response = requests.post(url, headers=headers)
    
    ```
* **繞過技術**: 使用 AMSI (Antimalware Scan Interface) 的 Full Mode 來繞過攻擊

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\exploit.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SharePoint_Server_Exploit {
        meta:
            description = "Detects SharePoint Server Exploit"
            author = "Your Name"
        strings:
            $a = "https://example.com/_api/contextinfo"
        condition:
            $a
    }
    
    ```
* **緩解措施**: 更新 SharePoint Server 和 Active Directory Federation Services 至最新版本，啟用 AMSI 的 Full Mode

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AMSI (Antimalware Scan Interface)**: 一個 Windows API，允許應用程式掃描檔案和記憶體中的惡意軟體
* **Elevation of Privilege (LPE)**: 一種攻擊方式，允許攻擊者提升自己的權限
* **SharePoint Server**: 一個 Microsoft 的網路應用程式伺服器，允許使用者存儲和管理檔案和資料

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/microsoft-patches-record-622-flaws.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


