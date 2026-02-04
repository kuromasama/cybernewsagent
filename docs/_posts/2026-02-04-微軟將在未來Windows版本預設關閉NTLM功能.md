---
layout: post
title:  "微軟將在未來Windows版本預設關閉NTLM功能"
date:   2026-02-04 06:42:15 +0000
categories: [security]
severity: high
---

# 🔥 解析 NTLM 退役對 Windows 安全性的影響
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: 身份驗證繞過、重送攻擊
> * **關鍵技術**: NTLM、Kerberos、身份驗證協定

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NTLM 的設計缺陷使其容易受到重送攻擊和中繼攻擊，且其加密機制相對較弱。
* **攻擊流程圖解**: 
  1. 攻擊者截獲 NTLM 驗證請求
  2. 攻擊者重送截獲的驗證請求
  3. 伺服器驗證通過，攻擊者取得存取權
* **受影響元件**: Windows NT、Windows 2000、Windows XP、Windows Vista、Windows 7、Windows 8、Windows 10、Windows 11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要截獲 NTLM 驗證請求
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 截獲 NTLM 驗證請求
    ntlm_request = requests.get('https://example.com', auth=('username', 'password'))
    
    # 重送截獲的驗證請求
    requests.get('https://example.com', auth=ntlm_request.auth)
    
    ```
* **繞過技術**: 可以使用工具如 `ntlmrelayx` 來繞過 NTLM 驗證

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\NTLM.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NTLM_Attack {
      meta:
        description = "NTLM 攻擊偵測"
        author = "Your Name"
      strings:
        $ntlm_request = "NTLMSSP\x00"
      condition:
        $ntlm_request at 0
    }
    
    ```
* **緩解措施**: 啟用 Kerberos 驗證，停用 NTLM 驗證

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NTLM (NT LAN Manager)**: 一種用於 Windows 網路和單機身分驗證的身份驗證協定。比喻：想像兩個人同時去改同一本帳簿，NTLM 就是用來確保只有授權的人才能改這本帳簿。
* **Kerberos**: 一種更安全的身份驗證協定，使用加密和票證機制來驗證使用者。技術上是指使用 Kerberos 協定來驗證使用者，然後使用票證機制來存取資源。
* **重送攻擊 (Replay Attack)**: 攻擊者截獲一個合法的驗證請求，然後重送這個請求來取得存取權。技術上是指攻擊者使用截獲的驗證請求來模擬合法使用者。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173753)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/)


