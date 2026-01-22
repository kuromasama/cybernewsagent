---
layout: post
title:  "NoSQL資料庫Firestore企業版換新查詢引擎，可串接多階段複雜資料轉換"
date:   2026-01-22 06:26:26 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Google Firebase Firestore 企業版查詢引擎更新：Pipeline Operations 與索引策略變更

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：未提供)
> * **受駭指標**: 資料查詢效能降低、索引管理複雜度增加
> * **關鍵技術**: NoSQL 資料庫、查詢引擎、索引策略、Pipeline Operations

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Firestore 企業版的查詢引擎更新導入 Pipeline Operations，允許開發者以多階段方式描述資料轉換流程，但同時也改變了索引策略，預設不再自動建立單欄位索引。
* **攻擊流程圖解**: 
    1. 開發者使用 Pipeline Operations 建立複雜的查詢流程。
    2. 查詢引擎執行查詢流程，可能需要建立索引。
    3. 如果索引未建立，查詢效能可能降低。
* **受影響元件**: Firestore 企業版、Pipeline Operations、索引策略

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Firestore 企業版的使用權限和網路存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import firebase_admin
    from firebase_admin import credentials, firestore
    
    # 初始化 Firestore 連接
    cred = credentials.Certificate("path/to/serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    
    # 建立 Pipeline Operations 查詢流程
    query = db.collection("example").where("field", "==", "value")
    query = query.order_by("field")
    query = query.limit(10)
    
    # 執行查詢流程
    results = query.get()
    
    ```
    *範例指令*: 使用 `curl` 執行查詢流程

```

bash
curl -X GET \
  https://firestore.googleapis.com/v1/projects/your-project/databases/(default)/documents/example \
  -H 'Authorization: Bearer your-token' \
  -H 'Content-Type: application/json' \
  -d '{"where": {"field": "value"}, "orderBy": {"field": "asc"}, "limit": 10}'

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用不同的 HTTP 方法或修改查詢參數。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Firestore_Pipeline_Operations {
        meta:
            description = "Detects Firestore Pipeline Operations queries"
            author = "Your Name"
        strings:
            $query = "where" wide
            $orderBy = "orderBy" wide
            $limit = "limit" wide
        condition:
            $query and $orderBy and $limit
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)

```

sql
index=firestore sourcetype=queries 

| stats count as query_count by user, query
| where query_count > 10
```
* **緩解措施**: 
    1. 更新 Firestore 企業版查詢引擎。
    2. 建立索引以改善查詢效能。
    3. 監控查詢流程和索引建立。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NoSQL 資料庫**: 一種不使用傳統的表格結構來存儲資料的資料庫，例如 Firestore、MongoDB。
* **查詢引擎**: 一種負責執行查詢的軟體元件，例如 Firestore 的查詢引擎。
* **索引策略**: 一種用於改善查詢效能的方法，例如自動建立索引、手動建立索引。
* **Pipeline Operations**: 一種允許開發者以多階段方式描述資料轉換流程的功能，例如 Firestore 的 Pipeline Operations。

## 5. 🔗 參考文獻與延伸閱讀
- [Google Firebase Firestore 文件](https://firebase.google.com/docs/firestore)
- [Pipeline Operations 文件](https://firebase.google.com/docs/firestore/query-data/pipeline-operations)


