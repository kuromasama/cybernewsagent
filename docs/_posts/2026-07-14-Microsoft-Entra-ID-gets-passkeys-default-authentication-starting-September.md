---
layout: post
title:  "Microsoft Entra ID gets passkeys default authentication starting September"
date:   2026-07-14 13:17:22 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Entra ID 的 Passkey 預設驗證機制與潛在安全威脅

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Credential Theft
> * **關鍵技術**: Passkey, FIDO2, Phishing-Resistant Authentication

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Entra ID 的 SMS 和語音驗證方法容易受到釣魚攻擊，導致用戶憑證被竊取。
* **攻擊流程圖解**: 
    1. 攻擊者發送釣魚郵件或短信給用戶。
    2. 用戶點擊連結或回覆短信，導致攻擊者獲得用戶的憑證。
    3. 攻擊者使用竊取的憑證登入用戶的帳戶。
* **受影響元件**: Microsoft Entra ID 的 SMS 和語音驗證方法。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道用戶的電子郵件地址或電話號碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義釣魚郵件的內容
    email_content = """
        <html>
            <body>
                <h1>您的帳戶已被鎖定</h1>
                <p>請點擊以下連結解鎖您的帳戶</p>
                <a href="https://example.com/phishing">解鎖帳戶</a>
            </body>
        </html>
    """
    
    # 發送釣魚郵件
    requests.post("https://example.com/send_email", data={"email": "user@example.com", "content": email_content})
    
    ```
    * **範例指令**: 使用 `curl` 發送釣魚郵件。

```

bash
curl -X POST \
  https://example.com/send_email \
  -H 'Content-Type: application/json' \
  -d '{"email": "user@example.com", "content": "<html>...</html>"}'

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全措施，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /phishing |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule phishing_email {
        meta:
            description = "釣魚郵件"
            author = "Your Name"
        strings:
            $email_content = "<html>...</html>"
        condition:
            $email_content
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=smtp | search "phishing" | stats count by src_ip
    
    ```
* **緩解措施**: 啟用 Passkey 預設驗證機制，停用 SMS 和語音驗證方法。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Passkey**: 一種基於 FIDO2 的密碼驗證方法，使用公鑰加密和私鑰解密來保護用戶的憑證。
* **FIDO2**: 一種開放的標準，定義了基於公鑰加密的密碼驗證方法。
* **Phishing-Resistant Authentication**: 一種能夠抵禦釣魚攻擊的密碼驗證方法，例如 Passkey 和 FIDO2。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-entra-id-gets-passkeys-default-authentication-starting-september/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/)


