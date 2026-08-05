---
layout: post
title:  "AWS基礎模型服務Bedrock內建網路搜尋，模型可查詢近期資料並附來源"
date:   2026-08-05 13:50:51 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Amazon Bedrock 的 Web Search 功能與潛在安全風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `API 串接`, `知識圖譜`, `網頁索引`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Amazon Bedrock 的 Web Search 功能使用知識圖譜和網頁索引來提供答案，但如果攻擊者可以操控查詢條件，可能會導致敏感資訊洩露。
* **攻擊流程圖解**: `User Input -> Amazon Bedrock API -> 知識圖譜查詢 -> 網頁索引查詢 -> 回傳答案`
* **受影響元件**: Amazon Bedrock 的 Web Search 功能，特別是使用 OpenAI 模型的應用程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Amazon Bedrock API 的存取權限和知識圖譜的相關知識。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義查詢條件
    query = "敏感資訊"
    
    # 送出查詢請求
    response = requests.post("https://api.amazonbedrock.com/search", json={"query": query})
    
    # 解析回傳答案
    answer = response.json()["answer"]
    
    # 判斷是否包含敏感資訊
    if "敏感資訊" in answer:
        print("Info Leak!")
    
    ```
* **繞過技術**: 攻擊者可以使用代理伺服器或 VPN 來繞過 IP 限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | api.amazonbedrock.com | /search |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule AmazonBedrock_InfoLeak {
        meta:
            description = "Amazon Bedrock Info Leak"
            author = "Your Name"
        strings:
            $query = "敏感資訊"
        condition:
            $query in (http.request.body | http.request.uri)
    }
    
    ```
* **緩解措施**: Amazon Bedrock 可以實施 IP 限制、查詢條件過濾和答案內容審查。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **知識圖譜 (Knowledge Graph)**: 一種圖形結構的知識儲存方式，使用實體、關係和屬性來描述知識。
* **網頁索引 (Web Index)**: 一種索引結構，儲存網頁的相關資訊，例如網頁標題、內容和連結。
* **OpenAI 模型 (OpenAI Model)**: 一種人工智慧模型，使用深度學習算法來處理自然語言任務。

## 5. 🔗 參考文獻與延伸閱讀
- [Amazon Bedrock 官方文件](https://aws.amazon.com/tw/amazon-bedrock/)
- [OpenAI 官方文件](https://openai.com/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/)


