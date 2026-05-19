---
layout: post
title:  "The New Phishing Click: How OAuth Consent Bypasses MFA"
date:   2026-05-19 14:43:52 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OAuth 權限授予攻擊：從 EvilTokens 到 Toxic Combinations

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: OAuth 權限授予攻擊，可能導致敏感資料泄露
> * **關鍵技術**: OAuth、權限授予、Toxic Combinations

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OAuth 權限授予機制中的漏洞，允許攻擊者通過欺騙用戶授予不必要的權限。
* **攻擊流程圖解**:
  1. 攻擊者創建一個假的 OAuth 應用程序。
  2. 用戶授予假的 OAuth 應用程序權限。
  3. 攻擊者獲得用戶的 refresh token。
  4. 攻擊者使用 refresh token 獲取用戶的敏感資料。
* **受影響元件**: 所有使用 OAuth 的應用程序和服務。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個假的 OAuth 應用程序，並且需要用戶授予權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的 OAuth 應用程序的 client_id 和 client_secret
    client_id = "your_client_id"
    client_secret = "your_client_secret"
    
    # 用戶授予權限的授權碼
    authorization_code = "your_authorization_code"
    
    # 獲取 access token 和 refresh token
    response = requests.post(
        "https://example.com/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "https://example.com/callback",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    
    access_token = response.json()["access_token"]
    refresh_token = response.json()["refresh_token"]
    
    # 使用 refresh token 獲取用戶的敏感資料
    response = requests.get(
        "https://example.com/api/data",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    
    print(response.json())
    
    ```
* **繞過技術**: 攻擊者可以使用各種方法繞過 OAuth 的安全機制，例如使用假的 OAuth 應用程序、欺騙用戶授予權限等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /oauth/token |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OAuth_Token_Leak {
        meta:
            description = "OAuth Token Leak"
            author = "Your Name"
        strings:
            $token = "access_token=" wide
        condition:
            $token at @entry(0)
    }
    
    ```
* **緩解措施**:
  1. 使用安全的 OAuth 實現。
  2. 監控 OAuth 流量。
  3. 使用安全的授權碼和 refresh token。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth (Open Authorization)**: 一種授權框架，允許用戶授予第三方應用程序權限。
* **Refresh Token**: 一種特殊的 token，允許用戶在不需要重新授權的情況下獲得新的 access token。
* **Toxic Combinations**: 一種攻擊技術，允許攻擊者通過組合多個 OAuth 權限授予攻擊獲得更高的權限。

## 5. 🔗 參考文獻與延伸閱讀
* [OAuth 2.0](https://tools.ietf.org/html/rfc6749)
* [OAuth 權限授予攻擊](https://www.oauth.com/)
* [Toxic Combinations](https://www.toxiccombinations.com/)


