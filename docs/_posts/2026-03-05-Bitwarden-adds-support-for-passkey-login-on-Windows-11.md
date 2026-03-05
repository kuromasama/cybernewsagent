---
layout: post
title:  "Bitwarden adds support for passkey login on Windows 11"
date:   2026-03-05 01:25:28 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Bitwarden 的 Windows 11 Passkey 登入機制與其安全性

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Authentication Bypass
> * **關鍵技術**: FIDO2, Passkey, Cryptographic Challenges

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Bitwarden 的 Passkey 登入機制使用 FIDO2 安全金鑰簽名，然而，如果攻擊者能夠取得用戶的 Entra ID 和 Bitwarden Vault 中的 Passkey，就可能繞過傳統密碼登入的限制。
* **攻擊流程圖解**: 
    1. 攻擊者取得用戶的 Entra ID 和 Bitwarden Vault 中的 Passkey。
    2. 攻擊者使用取得的 Passkey 向 Windows 11 發送登入請求。
    3. Windows 11 驗證 Passkey 並授權登入。
* **受影響元件**: Windows 11、Bitwarden Vault、FIDO2 安全金鑰。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得用戶的 Entra ID 和 Bitwarden Vault 中的 Passkey。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 取得用戶的 Entra ID 和 Bitwarden Vault 中的 Passkey
    entra_id = "example_entra_id"
    passkey = "example_passkey"
    
    # 向 Windows 11 發送登入請求
    url = "https://example.com/login"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "entra_id": entra_id,
        "passkey": passkey
    }
    
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code == 200:
        print("登入成功")
    else:
        print("登入失敗")
    
    ```
* **繞過技術**: 攻擊者可以使用社交工程術或其他手法取得用戶的 Entra ID 和 Bitwarden Vault 中的 Passkey。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| example_hash | example_ip | example_domain | example_file_path |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Bitwarden_Passkey_Login {
        meta:
            description = "Bitwarden Passkey 登入偵測"
            author = "example_author"
        strings:
            $passkey_login = "passkey_login"
        condition:
            $passkey_login
    }
    
    ```
* **緩解措施**: 使用強密碼、啟用兩步驟驗證、定期更新軟件和作業系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **FIDO2 (快速身份驗證)**: 一種快速、安全的身份驗證標準，使用公鑰加密和安全金鑰簽名。
* **Passkey (密鑰)**: 一種用於身份驗證的密鑰，通常存儲在安全的金鑰庫中。
* **Cryptographic Challenges (密碼學挑戰)**: 一種用於驗證身份的密碼學技術，使用公鑰加密和安全金鑰簽名。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/bitwarden-adds-support-for-passkey-login-on-windows-11/)
- [FIDO2 官方網站](https://fidoalliance.org/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1556/)


