---
layout: post
title:  "Azure Cosmos DB漏洞曾可接管任意資料庫帳戶，私人網路隔離也可能失效"
date:   2026-08-01 08:09:12 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Azure Cosmos DB 的 CosmosEscape 漏洞：從 Gremlin 查詢到任意程式碼執行

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Gremlin 查詢、.NET 反射、簽章金鑰

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Azure Cosmos DB 處理 Gremlin 查詢的方式存在漏洞，系統會先將查詢轉換成 .NET 程式碼執行，但限制機制未完整阻擋 .NET 反射功能，導致攻擊者可以藉此讀寫檔案，最後在微軟後端系統執行任意程式碼。
* **攻擊流程圖解**:
  1. 攻擊者建立自己的資料庫並送出特製 Gremlin 查詢。
  2. 查詢被轉換成 .NET 程式碼並執行。
  3. 攻擊者利用 .NET 反射功能突破隔離環境。
  4. 攻擊者進入代替客戶執行查詢的資料庫閘道。
  5. 攻擊者透過簽章金鑰取得指定 Cosmos DB 帳戶的主要存取金鑰。
* **受影響元件**: Azure Cosmos DB 的 Gremlin 查詢功能，尤其是使用 .NET 反射的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要建立自己的資料庫並具有送出 Gremlin 查詢的權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    query = """
      // 利用 .NET 反射功能讀寫檔案
      var file = new System.IO.File();
      file.WriteAllText("C:\\\\path\\\\to\\\\file.txt", "Hello, World!");
    """
    # 送出查詢
    response = requests.post("https://example.cosmos.azure.com/databases/DB_ID/collections/COLLECTION_ID/docs", json={"query": query})
    
    ```
* **繞過技術**: 攻擊者可以利用 .NET 反射功能繞過 WAF 或 EDR 的檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.cosmos.azure.com | C:\\\\path\\\\to\\\\file.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule CosmosEscape {
      meta:
        description = "Detects CosmosEscape attacks"
      strings:
        $query = "var file = new System.IO.File();"
      condition:
        $query
    }
    
    ```
* **緩解措施**: 更新 Azure Cosmos DB 的 Gremlin 查詢功能至最新版本，並限制 .NET 反射功能的使用。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Gremlin 查詢**: 一種圖形查詢語言，用于查詢圖形資料庫。
* **.NET 反射**: 一種 .NET 技術，允許程式在執行期間檢視及呼叫型別與成員。
* **簽章金鑰**: 一種金鑰，用于驗證 Azure Cosmos DB 的存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177795)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


