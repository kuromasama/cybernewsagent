---
layout: post
title:  "Why Secrets in JavaScript Bundles are Still Being Missed"
date:   2026-01-20 12:35:18 +0000
categories: [security]
severity: critical
---

# 🚨 解析 JavaScript Bundle 中的敏感 Token 泄露：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: Sensitive Token Leak
> * **關鍵技術**: JavaScript Bundle, Token Leak, Single-Page Application (SPA)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 敏感 Token 在 JavaScript Bundle 中被硬編碼或未經適當保護，導致泄露。
* **攻擊流程圖解**: 
    1. 攻擊者獲取 JavaScript Bundle
    2. 攻擊者分析 Bundle 中的代碼
    3. 攻擊者找到敏感 Token
    4. 攻擊者利用 Token 進行未經授權的存取
* **受影響元件**: Single-Page Application (SPA) 使用 JavaScript Bundle 的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲取 JavaScript Bundle
* **Payload 建構邏輯**:

    ```
    
    javascript
        // 範例 Payload
        const token = '敏感Token';
        const url = 'https://example.com/api';
        fetch(url, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => response.json())
        .then(data => console.log(data));
    
    ```
    *範例指令*: 使用 `curl` 命令發送請求

```

bash
    curl -X GET \
    https://example.com/api \
    -H 'Authorization: Bearer 敏感Token'

```
* **繞過技術**: 攻擊者可以使用各種方法繞過安全措施，例如使用代理伺服器或修改 User Agent。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /path/to/bundle.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule SensitiveTokenLeak {
            meta:
                description = "偵測敏感 Token 泄露"
                author = "Your Name"
            strings:
                $token = "敏感Token"
            condition:
                $token
        }
    
    ```
    或者是使用 SIEM 查詢語法

```

sql
    SELECT * FROM logs WHERE message LIKE '%敏感Token%'

```
* **緩解措施**: 
    1. 使用安全的 Token 儲存機制
    2. 啟用安全的 HTTP Header
    3. 使用 Web Application Firewall (WAF) 來過濾請求

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Single-Page Application (SPA)**: 一種 Web 應用程式，使用單一 HTML 頁面來呈現所有內容。
* **JavaScript Bundle**: 一個包含多個 JavaScript 檔案的封裝，通常使用 Webpack 或 Rollup 來打包。
* **Token Leak**: 敏感 Token 的泄露，可能導致未經授權的存取。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/why-secrets-in-javascript-bundles-are.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


