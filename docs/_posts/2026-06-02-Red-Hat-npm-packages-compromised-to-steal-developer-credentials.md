---
layout: post
title:  "Red Hat npm packages compromised to steal developer credentials"
date:   2026-06-02 02:52:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Red Hat npm 套件劫持事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: npm 套件劫持、GitHub Actions 工作流、OAuth 權限授予

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者透過 GitHub Actions 工作流和 OAuth 權限授予機制，將惡意程式碼注入 Red Hat 的 npm 套件中。
* **攻擊流程圖解**:
  1. 攻擊者取得 Red Hat 員工的 GitHub 帳戶存取權。
  2. 攻擊者建立一個 GitHub Actions 工作流，該工作流會在套件安裝時執行惡意程式碼。
  3. 攻擊者使用 OAuth 權限授予機制，取得 npm 的發佈權限。
  4. 攻擊者將惡意程式碼注入 Red Hat 的 npm 套件中。
* **受影響元件**: Red Hat 的 32 個 npm 套件和 96 個版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得 Red Hat 員工的 GitHub 帳戶存取權和 npm 的發佈權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意程式碼範例
    const { exec } = require('child_process');
    const { OAuth2Client } = require('oauth2-client');
    
    // 取得 OAuth 權限授予機制的存取權
    const oauth2Client = new OAuth2Client(
      'client_id',
      'client_secret',
      'redirect_uri'
    );
    
    // 執行惡意程式碼
    exec('node index.js', (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    });
    
    ```
* **繞過技術**: 攻擊者可以使用 GitHub Actions 工作流和 OAuth 權限授予機制，繞過傳統的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_code {
      meta:
        description = "偵測惡意程式碼"
      strings:
        $a = "node index.js"
      condition:
        $a at entry_point
    }
    
    ```
* **緩解措施**: 更新 Red Hat 的 npm 套件至最新版本，撤銷受影響的 OAuth 權限授予機制，並監控 GitHub Actions 工作流的異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth2Client**: OAuth 2.0 的用戶端實現，提供了存取權授予機制。
* **GitHub Actions**: GitHub 的工作流自動化工具，允許用戶定義和執行工作流。
* **npm**: Node.js 的套件管理器，提供了套件的發佈和安裝功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


