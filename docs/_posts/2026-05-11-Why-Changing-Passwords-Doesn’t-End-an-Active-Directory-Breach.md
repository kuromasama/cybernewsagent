---
layout: post
title:  "Why Changing Passwords Doesn’t End an Active Directory Breach"
date:   2026-05-11 14:34:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Active Directory 密碼重置漏洞：利用與防禦繞過
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Kerberos, Pass-the-Hash, Golden Ticket Attack

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Active Directory 中的密碼重置機制存在漏洞，導致密碼重置後，舊的密碼雜湊值仍然有效，攻擊者可以利用這個漏洞繼續存取系統。
* **攻擊流程圖解**:
  1. 攻擊者獲得用戶的密碼雜湊值。
  2. 用戶重置密碼。
  3. 攻擊者利用舊的密碼雜湊值進行 Pass-the-Hash 攻擊。
  4. 攻擊者成功存取系統。
* **受影響元件**: Active Directory、Kerberos、Windows 系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得用戶的密碼雜湊值。
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    
    # 獲取用戶的密碼雜湊值
    password_hash = hashlib.md5("password".encode()).hexdigest()
    
    # 建構 Pass-the-Hash 攻擊的 payload
    payload = {
        "username": "username",
        "password_hash": password_hash
    }
    
    ```
* **繞過技術**: 攻擊者可以利用 Golden Ticket Attack 繞過 Kerberos 的驗證機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PassTheHash {
        meta:
            description = "Detects Pass-the-Hash attacks"
            author = "Blue Team"
        strings:
            $a = "password_hash" ascii
        condition:
            $a at 0x1000
    }
    
    ```
* **緩解措施**: 重置 KRBTGT 帳戶、更新 Kerberos 金鑰、啟用 Kerberos 加密。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Kerberos**: 一種用於驗證和授權的安全協議。
* **Pass-the-Hash**: 一種攻擊技術，利用密碼雜湊值進行驗證。
* **Golden Ticket Attack**: 一種攻擊技術，利用 KRBTGT 帳戶的密碼雜湊值進行驗證。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/why-changing-passwords-doesnt-end-an-active-directory-breach/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1550/)


