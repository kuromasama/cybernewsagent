---
layout: post
title:  "Where Multi-Factor Authentication Stops and Credential Abuse Starts"
date:   2026-03-05 12:43:24 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Windows 身分驗證繞過技術：多因素驗證的盲點
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: Credential-Based Compromise
> * **關鍵技術**: Kerberos, NTLM, Pass-the-Hash, Pass-the-Ticket

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows 身分驗證機制中的多個繞過點，包括 Interactive Windows logon、Direct RDP access、NTLM authentication、Kerberos ticket abuse 等。
* **攻擊流程圖解**:
  1. 攻擊者獲得用戶的密碼或 NTLM hash。
  2. 攻擊者使用獲得的密碼或 NTLM hash 進行 Interactive Windows logon 或 Direct RDP access。
  3. 如果系統使用 NTLM authentication，攻擊者可以使用 pass-the-hash 技術進行驗證。
  4. 如果系統使用 Kerberos，攻擊者可以使用 Kerberos ticket abuse 技術進行驗證。
* **受影響元件**: Windows 作業系統，特別是使用 Active Directory (AD) 的環境。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得用戶的密碼或 NTLM hash。
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    
    # NTLM hash
    ntlm_hash = hashlib.new('md4', b'password').digest()
    
    # Pass-the-Hash
    def pass_the_hash(ntlm_hash, target_system):
      # 使用 NTLM hash 進行驗證
      # ...
    
    ```
* **繞過技術**: 攻擊者可以使用 Kerberos ticket abuse 技術繞過多因素驗證。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `ntlm_hash` | `192.168.1.100` | `example.com` | `C:\Windows\Temp\malware.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Kerberos_Ticket_Abuse {
      meta:
        description = "Kerberos ticket abuse detection"
      strings:
        $kerberos_ticket = { 0x00 0x01 0x02 0x03 }
      condition:
        $kerberos_ticket at 0
    }
    
    ```
* **緩解措施**: 強制使用多因素驗證，限制 NTLM authentication，監控 Kerberos ticket 活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Kerberos**: 一種用於驗證的安全協議，使用 ticket-based 系統進行驗證。
* **NTLM (NT LAN Manager)**: 一種用於驗證的安全協議，使用 challenge-response 系統進行驗證。
* **Pass-the-Hash**: 一種攻擊技術，使用 NTLM hash 進行驗證，而不需要知道明文密碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/where-multi-factor-authentication-stops.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1550/)


