---
layout: post
title:  "A Glimpse into the “Search Your Target” Market for Stolen Credentials"
date:   2026-06-22 16:43:13 +0000
categories: [security]
severity: high
---

# 🔥 解析「搜尋您的目標」市場：威脅情報與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: 資料外洩與身份驗證攻擊
> * **關鍵技術**: 資料搜尋、過濾、格式化與交付

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 資料外洩與身份驗證攻擊的根源在於「搜尋您的目標」市場的出現，這個市場允許買家搜尋和提取特定的身份驗證資料。
* **攻擊流程圖解**:
  1. 資料收集：攻擊者使用 infostealer 來收集大量的身份驗證資料。
  2. 資料儲存：收集到的資料儲存於私有雲、ULP 數據庫、公開傾倒或交換式集合中。
  3. 資料搜尋：買家向賣家提交搜尋請求，賣家根據請求從儲存的資料中提取相關的身份驗證資料。
  4. 資料交付：賣家將搜尋結果交付給買家，買家可以使用這些資料進行身份驗證攻擊。
* **受影響元件**: 所有使用過網路服務的用戶和企業都可能受到影響。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一定的資源和技術能力來收集和儲存大量的身份驗證資料。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      {
        "target": "example.com",
        "credentials": [
          {"username": "user1", "password": "pass1"},
          {"username": "user2", "password": "pass2"}
        ]
      }
    
    ```
  * **範例指令**: 使用 `curl` 向賣家提交搜尋請求

```

bash
  curl -X POST \
  https://seller.example.com/search \
  -H 'Content-Type: application/json' \
  -d '{"target": "example.com"}'

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全措施，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /path/to/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule SearchYourTarget {
        meta:
          description = "搜尋您的目標市場的偵測規則"
          author = "Your Name"
        strings:
          $search_request = "GET /search?target=" nocase
        condition:
          $search_request in (http.request.uri)
      }
    
    ```
  * **SIEM 查詢語法**: 使用 Splunk 或 Elastic Search 來查詢相關的日誌資料

```

spl
  index=web_logs sourcetype=http_access \

| search "GET /search?target=" \
| stats count as num_requests by src_ip
```
* **緩解措施**: 使用強密碼、啟用雙因素身份驗證、定期更新軟體和系統等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Infostealer**: 一種惡意軟體，用于收集和竊取用戶的身份驗證資料。
* **ULP 數據庫**: 一種用於儲存和管理大量資料的數據庫。
* **Initial Access Broker (IAB)**: 一種提供初始存取權限的服務，允許買家購買和使用已經被攻擊的系統的存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/a-glimpse-into-the-search-your-target-market-for-stolen-credentials/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1589/)


