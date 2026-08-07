---
layout: post
title:  "資安業者揭露Claude分享對話可被Google搜尋，恐導致用戶敏感資訊意外曝光"
date:   2026-08-07 12:45:41 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Claude 對話分享功能的資訊洩露漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `分享連結`, `搜尋引擎索引`, `對話狀態轉為Public`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude 對話分享功能會為對話建立可供他人存取的分享連結，同時將對話狀態轉為 Public。這使得搜尋引擎可以索引這些公開分享的對話，從而出現在搜尋結果中。
* **攻擊流程圖解**: 
    1. User 使用 Claude 對話分享功能分享對話。
    2. Claude 對話分享功能建立可供他人存取的分享連結。
    3. 對話狀態轉為 Public。
    4. 搜尋引擎索引公開分享的對話。
    5. 對話出現在搜尋結果中。
* **受影響元件**: Claude 對話分享功能，Google 搜尋引擎。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要 Claude 對話分享功能的使用權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建立分享連結
    share_link = "https://example.com/claude-share-link"
    
    # 對話狀態轉為 Public
    response = requests.get(share_link)
    
    # 搜尋引擎索引公開分享的對話
    search_query = "site:example.com inurl:claude-share-link"
    search_response = requests.get(f"https://www.google.com/search?q={search_query}")
    
    # 對話出現在搜尋結果中
    if search_response.status_code == 200:
        print("對話已經被搜尋引擎索引")
    
    ```
    *範例指令*: 使用 `curl` 命令建立分享連結和對話狀態轉為 Public。

```

bash
curl -X GET "https://example.com/claude-share-link"
curl -X GET "https://www.google.com/search?q=site:example.com+inurl:claude-share-link"

```
* **繞過技術**: 可以使用代理伺服器或 VPN 來繞過搜尋引擎的 IP 限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /claude-share-link |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Claude_Share_Link {
        meta:
            description = "Detect Claude share link"
            author = "Your Name"
        strings:
            $share_link = "https://example.com/claude-share-link"
        condition:
            $share_link
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
index=web_logs sourcetype=access_combined | search "https://example.com/claude-share-link"

```
* **緩解措施**: 除了 Patch 之外的 Config 修改建議，例如設定 Claude 對話分享功能的權限和搜尋引擎的索引限制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **分享連結 (Share Link)**: 一個可供他人存取的連結，允許他人查看或編輯共享的內容。技術上是指一個 URL 連結，包含了共享內容的 ID 和權限信息。
* **搜尋引擎索引 (Search Engine Indexing)**: 搜尋引擎對網頁內容的索引和儲存，允許用戶通過搜尋引擎查找和訪問網頁內容。技術上是指搜尋引擎的爬蟲程式對網頁內容的抓取和分析。
* **對話狀態轉為 Public (Conversation Status Changed to Public)**: 對話的狀態從私有轉為公開，允許他人查看或編輯對話內容。技術上是指對話的權限信息被修改，允許他人存取對話內容。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177976)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1056/)


