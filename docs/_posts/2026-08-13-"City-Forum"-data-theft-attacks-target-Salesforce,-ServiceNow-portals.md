---
layout: post
title:  ""City-Forum" data-theft attacks target Salesforce, ServiceNow portals"
date:   2026-08-13 01:18:15 +0000
categories: [security]
severity: high
---

# 🔥 解析 City-Forum 資料竊取攻擊：Salesforce Experience Cloud 和 ServiceNow 客戶門戶漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: 資料洩露 (Data Leak)
> * **關鍵技術**: REST API、GraphQL、客戶門戶配置

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Salesforce Experience Cloud 和 ServiceNow 客戶門戶的配置問題，導致未經驗證的使用者可以存取敏感資料。
* **攻擊流程圖解**:
  1. 攻擊者發送請求到 Salesforce Experience Cloud 或 ServiceNow 客戶門戶的 API 端點。
  2. 如果配置允許，攻擊者可以存取敏感資料。
  3. 攻擊者使用 GraphQL 或 REST API 來枚舉和存取資料。
* **受影響元件**:
  * Salesforce Experience Cloud
  * ServiceNow 客戶門戶

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 無需驗證即可存取 Salesforce Experience Cloud 或 ServiceNow 客戶門戶。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Salesforce Experience Cloud
    url = "https://example.my.salesforce.com/s/sfsites/aura"
    response = requests.get(url)
    
    # ServiceNow 客戶門戶
    url = "https://example.service-now.com/api/now/sp/search"
    response = requests.post(url, json={"sysparm_cancelable": True})
    
    ```
* **繞過技術**: 無需繞過技術，因為攻擊者可以直接存取敏感資料。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 158.220.87.79 | city-forum.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Salesforce_Experience_Cloud_Attack {
      meta:
        description = "Salesforce Experience Cloud 攻擊"
      strings:
        $a = "s/sfsites/aura"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**:
  * 檢查 Salesforce Experience Cloud 和 ServiceNow 客戶門戶的配置，確保只有授權使用者可以存取敏感資料。
  * 啟用驗證和授權機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GraphQL**: 一種查詢語言，允許客戶端指定需要的資料。
* **REST API**: 一種基於 HTTP 的 API，允許客戶端存取和操作資料。
* **客戶門戶配置**: 客戶門戶的設定和配置，控制使用者存取敏感資料的權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/city-forum-data-theft-attacks-target-salesforce-servicenow-portals/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


