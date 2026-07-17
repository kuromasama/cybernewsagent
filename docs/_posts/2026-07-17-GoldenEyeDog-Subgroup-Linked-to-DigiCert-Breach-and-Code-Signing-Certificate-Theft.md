---
layout: post
title:  "GoldenEyeDog Subgroup Linked to DigiCert Breach and Code-Signing Certificate Theft"
date:   2026-07-17 18:57:44 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CylindricalCanine 威脅群體的 Golden Gh0st RAT 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Gh0st RAT, Code Signing Certificate, DLL Side-Loading

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CylindricalCanine 威脅群體利用 Golden Gh0st RAT 攻擊 DigiCert 的支持人員，竊取 code signing certificate，進而簽署惡意軟體以避免檢測。
* **攻擊流程圖解**:
  1. 攻擊者透過客戶聊天頻道傳送惡意 ZIP 檔案。
  2. ZIP 檔案包含一個 .scr 執行檔，內含惡意 payload。
  3. 支持人員執行 .scr 檔案，導致惡意 payload 被執行。
  4. 惡意 payload 利用 DLL side-loading 技術，載入 Golden Gh0st RAT。
* **受影響元件**: DigiCert Trusted G4 Code Signing RSA4096 SHA256 2021 CA1, DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1, Verokey High Assurance Secure Code EV

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 DigiCert 支持人員的帳戶資訊。
* **Payload 建構邏輯**:

    ```
    
    python
    # Golden Gh0st RAT Payload
    import os
    import sys
    
    # DLL side-loading
    dll_path = "C:\\Windows\\System32\\msvcrt.dll"
    payload_path = "C:\\Windows\\Temp\\update.log"
    
    # 執行 DLL side-loading
    os.system(f"rundll32.exe {dll_path},DllMain {payload_path}")
    
    ```
* **繞過技術**: 攻擊者可以利用 code signing certificate 簽署惡意軟體，以避免被防毒軟體檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\\Windows\\Temp\\update.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Golden_Gh0st_RAT {
      meta:
        description = "Golden Gh0st RAT Malware"
        author = "Your Name"
      strings:
        $a = "msvcrt.dll"
        $b = "update.log"
      condition:
        all of them
    }
    
    ```
* **緩解措施**: 更新 DigiCert 支持人員的帳戶資訊，啟用兩步驟驗證，並限制支持人員的權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Gh0st RAT (遠程存取木馬)**: 一種遠程存取木馬，允許攻擊者控制受害者的電腦。
* **Code Signing Certificate (代碼簽署憑證)**: 一種憑證，用于驗證軟體的真實性和完整性。
* **DLL Side-Loading (DLL 側載)**: 一種技術，允許攻擊者載入惡意 DLL 檔案，以避免被防毒軟體檢測。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


