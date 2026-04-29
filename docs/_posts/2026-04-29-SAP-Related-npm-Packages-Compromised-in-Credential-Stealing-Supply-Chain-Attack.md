---
layout: post
title:  "SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack"
date:   2026-04-29 19:14:15 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SAP 相關 npm 套件的供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credential Stealing 和 RCE (Remote Code Execution)
> * **關鍵技術**: Supply Chain Attack, npm 套件劫持, Credential Stealing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者通過劫持 SAP 相關的 npm 套件（例如 `mbt`、`@cap-js/db-service` 等），在套件的 `preinstall` 腳本中添加了惡意代碼，從而實現了供應鏈攻擊。
* **攻擊流程圖解**:
  1. 攻擊者劫持 npm 套件的發佈權限。
  2. 攻擊者在套件的 `preinstall` 腳本中添加惡意代碼。
  3. 使用者安裝受影響的套件時，惡意代碼被執行。
  4. 惡意代碼下載並執行額外的惡意程式碼，實現 Credential Stealing 和 RCE。
* **受影響元件**: 受影響的套件版本包括 `mbt@1.2.48`、`@cap-js/db-service@2.10.1` 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 npm 套件的發佈權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意代碼範例
    const { exec } = require('child_process');
    exec('powershell -ExecutionPolicy Bypass -File setup.mjs', (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    });
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用 PowerShell 的 `-ExecutionPolicy Bypass` 參數來繞過執行原則限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_script {
      meta:
        description = "Detects malicious script"
      strings:
        $a = "powershell -ExecutionPolicy Bypass"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 使用者應該更新受影響的套件版本，並啟用安全防護機制，例如限制 PowerShell 的執行原則。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，如同一條長長的鏈子，攻擊者可以在鏈子的任何一個環節進行攻擊，從而影響整個供應鏈。技術上是指攻擊者通過劫持或操縱供應鏈中的某個環節（例如軟件套件、元件等），從而實現對最終使用者的攻擊。
* **npm (Node Package Manager)**: Node.js 的套件管理工具，允許使用者輕鬆地安裝和管理套件。
* **Credential Stealing (憑證竊取)**: 攻擊者竊取使用者的憑證（例如密碼、令牌等），從而實現未經授權的訪問。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


