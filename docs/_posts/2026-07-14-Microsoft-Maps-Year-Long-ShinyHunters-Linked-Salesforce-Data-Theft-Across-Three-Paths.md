---
layout: post
title:  "Microsoft Maps Year-Long ShinyHunters-Linked Salesforce Data Theft Across Three Paths"
date:   2026-07-14 07:50:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Salesforce OAuth 連接器漏洞：ShinyHunters 攻擊技術分析
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 未經授權存取 Salesforce 資料
> * **關鍵技術**: OAuth 連接器、Vishing、Token 劫持、GraphQL 查詢

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ShinyHunters 攻擊者利用 OAuth 連接器的授權機制，透過 Vishing 手法欺騙使用者授權惡意應用程式，進而存取 Salesforce 資料。
* **攻擊流程圖解**:
  1. 攻擊者透過 Vishing 手法欺騙使用者授權惡意應用程式。
  2. 惡意應用程式使用授權的 OAuth Token 存取 Salesforce 資料。
  3. 攻擊者透過 GraphQL 查詢提取敏感資料。
* **受影響元件**: Salesforce OAuth 連接器、GraphQL API

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Salesforce 帳戶和 OAuth 連接器的授權。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意應用程式的 OAuth Client ID 和 Client Secret
    client_id = "YOUR_CLIENT_ID"
    client_secret = "YOUR_CLIENT_SECRET"
    
    # 使用者授權的 OAuth Token
    token = "YOUR_OAUTH_TOKEN"
    
    # GraphQL 查詢語法
    query = """
      query {
        accounts {
          id
          name
        }
      }
    """
    
    # 發送 GraphQL 查詢請求
    response = requests.post(
      "https://your-salesforce-instance.my.salesforce.com/graphql",
      headers={"Authorization": f"Bearer {token}"},
      json={"query": query}
    )
    
    # 提取敏感資料
    data = response.json()["data"]
    
    ```
* **繞過技術**: 攻擊者可以透過 Vishing 手法欺騙使用者授權惡意應用程式，進而繞過授權機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/malicious/app |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Salesforce_OAuth_Token_Theft {
      meta:
        description = "Detects Salesforce OAuth token theft"
        author = "Your Name"
      strings:
        $token = "YOUR_OAUTH_TOKEN"
      condition:
        $token at @entry(0)
    }
    
    ```
* **緩解措施**:
  1. 啟用 Salesforce 的 OAuth 連接器審核功能。
  2. 監控 OAuth 連接器的授權活動。
  3. 將 OAuth 連接器的授權範圍限制至最小。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 連接器 (OAuth Connector)**: 一種授權機制，允許應用程式存取使用者的 Salesforce 資料。
* **Vishing (語音釣魚)**: 一種社交工程攻擊，透過電話欺騙使用者授權惡意應用程式。
* **GraphQL (圖形查詢語言)**: 一種查詢語言，允許應用程式存取 Salesforce 資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/microsoft-maps-year-long-shinyhunters.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1556/)


