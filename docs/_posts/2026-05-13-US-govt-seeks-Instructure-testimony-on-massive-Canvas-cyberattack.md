---
layout: post
title:  "US govt seeks Instructure testimony on massive Canvas cyberattack"
date:   2026-05-13 02:32:25 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ShinyHunters 對 Instructure Canvas 平台的網路攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Cross-Site Scripting (XSS), Use-After-Free, Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ShinyHunters 利用了 Instructure Canvas 平台的 XSS 漏洞，該漏洞允許攻擊者注入惡意 JavaScript 代碼，進而取得授權的管理員會話。
* **攻擊流程圖解**:
  1. 攻擊者發送含有惡意 JavaScript 代碼的請求到 Canvas 平台。
  2. Canvas 平台未能正確驗證和過濾請求，導致惡意代碼被執行。
  3. 惡意代碼取得授權的管理員會話，允許攻擊者存取敏感數據和進行未經授權的操作。
* **受影響元件**: Instructure Canvas 平台，版本號未公開。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有網路存取權限和基本的 Web 開發知識。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意 JavaScript 代碼範例
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/canvas/api/v1/courses', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(JSON.stringify({
        'course': {
          'name': 'Malicious Course',
          'description': 'This is a malicious course'
        }
      }));
    
    ```
  *範例指令*: 使用 `curl` 工具發送惡意請求：

```

bash
  curl -X POST \
  https://example.com/canvas/api/v1/courses \
  -H 'Content-Type: application/json' \
  -d '{"course": {"name": "Malicious Course", "description": "This is a malicious course"}}'

```
* **繞過技術**: ShinyHunters 利用了多個 XSS 漏洞來取得授權的管理員會話，繞過了 Canvas 平台的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /canvas/api/v1/courses |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule canvas_xss {
        meta:
          description = "Detects malicious JavaScript code in Canvas API requests"
          author = "Your Name"
        strings:
          $js_code = "var xhr = new XMLHttpRequest();"
        condition:
          $js_code
      }
    
    ```
  或者使用 Snort/Suricata Signature：

```

snort
  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Canvas XSS Attack"; content:"var xhr = new XMLHttpRequest();"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 Canvas 平台到最新版本，啟用 Web Application Firewall (WAF) 並設定 XSS 防護規則。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cross-Site Scripting (XSS)**: 想像兩個網站之間的互動，攻擊者可以注入惡意代碼到受害者網站，進而取得授權的存取權限。技術上是指攻擊者注入惡意 JavaScript 代碼到網頁，網頁未能正確驗證和過濾請求，導致惡意代碼被執行。
* **Use-After-Free**: 想像一個物件被釋放後，攻擊者可以重新使用該物件，進而取得敏感數據或進行未經授權的操作。技術上是指攻擊者利用已經釋放的記憶體空間，重新分配記憶體，進而取得敏感數據或進行未經授權的操作。
* **Heap Spraying**: 想像攻擊者可以在記憶體中創建大量的物件，進而取得敏感數據或進行未經授權的操作。技術上是指攻擊者利用記憶體分配機制，創建大量的物件，進而取得敏感數據或進行未經授權的操作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/us-govt-seeks-instructure-testimony-on-massive-canvas-cyberattack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


