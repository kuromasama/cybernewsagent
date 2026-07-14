---
layout: post
title:  "11 Old Microsoft-Signed Linux UEFI Shims Could Let Attackers Bypass Secure Boot"
date:   2026-07-14 13:16:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 UEFI Secure Boot 繞過技術：利用過期的 Microsoft 簽名 UEFI 應用程式
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: UEFI Secure Boot, Microsoft 簽名 UEFI 應用程式, Shim Bootloader

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: UEFI Secure Boot 機制允許使用 Microsoft 簽名的 UEFI 應用程式，但如果這些應用程式過期或存在漏洞，攻擊者可以利用它們繞過 Secure Boot 的保護。
* **攻擊流程圖解**:
  1. 攻擊者取得過期的 Microsoft 簽名 UEFI 應用程式。
  2. 攻擊者修改 UEFI 應用程式的簽名，讓它可以被 UEFI firmware 認證。
  3. 攻擊者將修改過的 UEFI 應用程式載入到系統中。
  4. UEFI firmware 將修改過的 UEFI 應用程式認證為合法的簽名。
  5. 攻擊者可以執行任意代碼，繞過 Secure Boot 的保護。
* **受影響元件**: UEFI firmware、Microsoft 簽名 UEFI 應用程式、Shim Bootloader

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得過期的 Microsoft 簽名 UEFI 應用程式和 UEFI firmware 的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    payload = {
        'uefi_app': '過期的 Microsoft 簽名 UEFI 應用程式',
        'signature': '修改過的簽名',
        'code': '任意代碼'
    }
    
    ```
* **繞過技術**: 攻擊者可以使用 Shim Bootloader 的漏洞來繞過 Secure Boot 的保護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /boot/efi/EFI/BOOTX64.EFI |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule UEFI_Secure_Boot_Bypass {
        meta:
            description = "UEFI Secure Boot 繞過技術"
            author = "Your Name"
        strings:
            $uefi_app = "過期的 Microsoft 簽名 UEFI 應用程式"
            $signature = "修改過的簽名"
        condition:
            $uefi_app and $signature
    }
    
    ```
* **緩解措施**: 更新 UEFI firmware 和 Microsoft 簽名 UEFI 應用程式，使用 Shim Bootloader 的最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **UEFI Secure Boot**: 一種安全機制，確保系統只執行合法的 UEFI 應用程式。
* **Shim Bootloader**: 一種開源的 UEFI Bootloader，允許 Linux 系統在 UEFI Secure Boot 下執行。
* **Microsoft 簽名 UEFI 應用程式**: Microsoft 簽名的 UEFI 應用程式，可以被 UEFI firmware 認證為合法的簽名。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/11-old-microsoft-signed-linux-uefi.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1542/)


