---
layout: post
title:  "Claude Code source code accidentally leaked in NPM package"
date:   2026-04-01 01:57:32 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Claude Code 源碼洩露事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Source Map, JavaScript, NPM

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude Code 的開發團隊在發布新版本時，意外地將內部源碼包含在了 NPM 包中。這是因為 `cli.js.map` 檔案中包含了原始源碼的內容，導致了源碼洩露。
* **攻擊流程圖解**: 
    1. Anthropic 發布新版本的 Claude Code
    2. NPM 包中包含 `cli.js.map` 檔案
    3. 攻擊者下載 NPM 包並提取 `cli.js.map` 檔案
    4. 攻擊者使用 Source Map 工具重建原始源碼
* **受影響元件**: Claude Code 版本 2.1.88

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路連接、NPM 包下載權限
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const sourceMap = require('source-map');
    const cliJsMap = fs.readFileSync('cli.js.map', 'utf8');
    const sourceCode = sourceMap.SourceMapConsumer.fromSourceMap(cliJsMap);
    console.log(sourceCode.sourcesContent);
    
    ```
    * **範例指令**: 使用 `curl` 下載 NPM 包，然後使用 `source-map` 工具重建原始源碼
* **繞過技術**: 無

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | `cli.js.map` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Claude_Code_Source_Map {
        meta:
            description = "Detects Claude Code source map file"
            author = "Your Name"
        strings:
            $source_map = "sourcesContent"
        condition:
            $source_map at 0
    }
    
    ```
    * **SIEM 查詢語法**: `index=logs sourcetype=npm_download | regex "cli.js.map"`
* **緩解措施**: 更新 Claude Code 版本，移除 `cli.js.map` 檔案

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Source Map (源碼映射)**: 一種將編譯後的程式碼映射回原始源碼的技術。它允許開發人員在調試編譯後的程式碼時，仍然可以看到原始源碼的內容。
* **NPM (Node Package Manager)**: 一種 Node.js 的套件管理工具。它允許開發人員輕鬆地安裝、更新和管理 Node.js 的套件。
* **JavaScript (JavaScript)**: 一種高級的、動態的、基於原型的程式語言。它常用於網頁開發、移動應用開發和伺服器端開發。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/artificial-intelligence/claude-code-source-code-accidentally-leaked-in-npm-package/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1005/)


