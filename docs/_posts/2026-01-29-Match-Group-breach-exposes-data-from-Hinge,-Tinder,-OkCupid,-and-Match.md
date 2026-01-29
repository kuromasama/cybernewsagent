---
layout: post
title:  "Match Group breach exposes data from Hinge, Tinder, OkCupid, and Match"
date:   2026-01-29 18:35:58 +0000
categories: [security]
severity: high
---

# 🔥 解析 Match Group 資安事件：ShinyHunters 威脅群體的社會工程攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: 社會工程、單點登入 (SSO)、Okta、Google Drive、Dropbox

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Match Group 的 Okta SSO 帳戶被 ShinyHunters 威脅群體透過社會工程攻擊取得，進而存取公司的 AppsFlyer 行銷分析實例和 Google Drive、Dropbox 雲儲存帳戶。
* **攻擊流程圖解**: 
  1. 社會工程攻擊 -> 獲取 Okta SSO 帳戶密碼
  2. Okta SSO 帳戶 -> AppsFlyer 行銷分析實例
  3. AppsFlyer 行銷分析實例 -> Google Drive 和 Dropbox 雲儲存帳戶
* **受影響元件**: Okta SSO、AppsFlyer 行銷分析實例、Google Drive、Dropbox

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有目標公司的員工電子郵件地址和電話號碼
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 社會工程攻擊的 payload
    payload = {
        "username": "員工電子郵件地址",
        "password": "員工密碼"
    }
    
    # 發送請求到 Okta SSO 登入頁面
    response = requests.post("https://example.okta.com/login", data=payload)
    
    # 如果登入成功，則存取 AppsFlyer 行銷分析實例和 Google Drive、Dropbox 雲儲存帳戶
    if response.status_code == 200:
        # 存取 AppsFlyer 行銷分析實例
        appsflyer_response = requests.get("https://example.appsflyer.com/dashboard")
        # 存取 Google Drive 和 Dropbox 雲儲存帳戶
        google_drive_response = requests.get("https://drive.google.com/drive")
        dropbox_response = requests.get("https://www.dropbox.com")
    
    ```
* **繞過技術**: 可以使用 VPN 和代理伺服器來繞過公司的防火牆和入侵偵測系統

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 192.0.2.1 |
| Domain | example.okta.com |
| File Path | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Okta_SSO_Login {
      meta:
        description = "Okta SSO 登入頁面"
        author = "Your Name"
      strings:
        $okta_login = "https://example.okta.com/login"
      condition:
        $okta_login
    }
    
    ```
 

```

snort
alert tcp any any -> any 80 (msg:"Okta SSO 登入頁面"; content:"https://example.okta.com/login"; sid:1000001; rev:1;)

```
* **緩解措施**: 啟用多因素驗證 (MFA) 和單點登入 (SSO) 的安全設定，例如使用 FIDO2 安全金鑰或密碼

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社會工程 (Social Engineering)**: 一種攻擊手法，利用人類心理和行為的弱點來取得敏感資訊或存取系統。
* **單點登入 (SSO)**: 一種安全機制，允許用戶使用單一帳戶和密碼存取多個系統和應用程式。
* **Okta**: 一家提供身份和存取管理解決方案的公司，包括單點登入 (SSO) 和多因素驗證 (MFA)。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/match-group-breach-exposes-data-from-hinge-tinder-okcupid-and-match/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


