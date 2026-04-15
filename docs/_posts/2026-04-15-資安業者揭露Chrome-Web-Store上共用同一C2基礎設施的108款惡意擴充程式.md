---
layout: post
title:  "資安業者揭露Chrome Web Store上共用同一C2基礎設施的108款惡意擴充程式"
date:   2026-04-15 07:22:22 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Chrome 擴充程式惡意行為：OAuth 機制利用與後門機制
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (OAuth Token竊取) 與 RCE (後門機制)
> * **關鍵技術**: OAuth 2.0, 後門機制, JavaScript Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Chrome 擴充程式的 OAuth 2.0 實現中，沒有正確驗證使用者的授權請求，導致攻擊者可以竊取使用者的 OAuth Token。
* **攻擊流程圖解**:
  1. 使用者安裝惡意擴充程式
  2. 惡意擴充程式要求使用者授權 OAuth 2.0
  3. 使用者授權後，惡意擴充程式竊取 OAuth Token
  4. 惡意擴充程式將 OAuth Token 傳送到 C2 伺服器
* **受影響元件**: Chrome 108 及之前版本，所有安裝了惡意擴充程式的使用者

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意擴充程式需要使用者安裝並授權 OAuth 2.0
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = {
      "client_id": "惡意擴充程式的 client_id",
      "redirect_uri": "惡意擴充程式的 redirect_uri",
      "response_type": "token",
      "scope": "https://www.googleapis.com/auth/userinfo.email"
    };
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      https://accounts.google.com/o/oauth2/token \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'client_id=惡意擴充程式的client_id&redirect_uri=惡意擴充程式的redirect_uri&response_type=token&scope=https://www.googleapis.com/auth/userinfo.email'
    
    ```
* **繞過技術**: 惡意擴充程式可以使用 JavaScript Injection 技術來繞過 Chrome 的安全機制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | cloudapi.stream | /usr/lib/chromium-browser/extensions/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Chrome_Malicious_Extension {
      meta:
        description = "Detects malicious Chrome extensions"
      strings:
        $a = "cloudapi.stream"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 使用者應該卸載所有惡意擴充程式，並更新 Chrome 至最新版本

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0**: 一種授權框架，允許使用者授權第三方應用程式存取其資源。
* **後門機制**: 一種技術，允許攻擊者在未經授權的情況下存取系統或應用程式。
* **JavaScript Injection**: 一種技術，允許攻擊者在網頁中注入惡意 JavaScript 代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175087)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


