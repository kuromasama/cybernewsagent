---
layout: post
title:  "144 Mastra npm Packages Compromised via Hijacked Contributor Account"
date:   2026-06-17 10:30:05 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Mastra Namespace 中的 npm 包劫持攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `npm 包劫持`, `postinstall hook`, `obfuscated payload`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者通過劫持 `ehindero` 帳戶，將惡意代碼注入到 Mastra Namespace 下的 144 個 npm 包中。這些包中包含了一個名為 `easy-day-js` 的第三方庫，該庫是一個 `dayjs` 日期庫的克隆版本，但包含了一個加密貨幣竊取的遠程存取木馬。
* **攻擊流程圖解**:
  1. 攻擊者劫持 `ehindero` 帳戶。
  2. 攻擊者將惡意代碼注入到 Mastra Namespace 下的 npm 包中。
  3. 受害者安裝受影響的 npm 包。
  4. `postinstall hook` 觸發，下載並執行惡意 payload。
  5. 惡意 payload 執行，竊取加密貨幣和敏感信息。
* **受影響元件**: Mastra Namespace 下的 144 個 npm 包，包括 `@mastra/core`。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要劫持 `ehindero` 帳戶，並將惡意代碼注入到 Mastra Namespace 下的 npm 包中。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // easy-day-js payload
    const payload = {
      "name": "easy-day-js",
      "version": "1.0.0",
      "description": "A date library",
      "main": "index.js",
      "scripts": {
        "postinstall": "node postinstall.js"
      },
      "dependencies": {
        "dayjs": "^1.10.4"
      }
    };
    
    // postinstall.js
    const childProcess = require('child_process');
    childProcess.exec('node payload.js');
    
    ```
* **繞過技術**: 攻擊者使用了 `postinstall hook` 來觸發惡意 payload 的下載和執行，同時使用了 obfuscated payload 來躲避偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 23.254.164.92 | example.com | /usr/lib/node_modules/easy-day-js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule easy_day_js {
      meta:
        description = "Detects easy-day-js payload"
      strings:
        $a = "node postinstall.js"
      condition:
        $a at @entry_point
    }
    
    ```
* **緩解措施**: 更新受影響的 npm 包，旋轉敏感信息，審計系統日誌以檢測是否有惡意活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm 包劫持**: 一種攻擊方式，攻擊者通過劫持 npm 包的發佈權限，將惡意代碼注入到包中。
* **postinstall hook**: 一種 npm 包的生命週期鉤子，當包安裝完成後會觸發。
* **obfuscated payload**: 一種加密或混淆的 payload，難以被偵測和分析。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


