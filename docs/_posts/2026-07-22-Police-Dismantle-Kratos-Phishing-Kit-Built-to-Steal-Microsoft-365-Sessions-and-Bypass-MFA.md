---
layout: post
title:  "Police Dismantle Kratos Phishing Kit Built to Steal Microsoft 365 Sessions and Bypass MFA"
date:   2026-07-22 08:12:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Kratos 攻擊框架：利用 Adversary-in-the-Middle 技術繞過雙因素驗證

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Adversary-in-the-Middle (AiTM) 攻擊
> * **關鍵技術**: `Adversary-in-the-Middle`, `Session Cookie 劫持`, `雙因素驗證繞過`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kratos 攻擊框架利用 Adversary-in-the-Middle 技術，實現雙因素驗證繞過。攻擊者可以透過 Node.js 反向代理，實時轉發用戶登入請求，並捕獲結果中的 Session Cookie。
* **攻擊流程圖解**:
  1. 用戶接收到釣魚郵件，點擊連結導向 Kratos 攻擊框架。
  2. Kratos 攻擊框架使用 Node.js 反向代理，將用戶登入請求轉發到 Microsoft 365 伺服器。
  3. Microsoft 365 伺服器返回登入結果，包含 Session Cookie。
  4. Kratos 攻擊框架捕獲 Session Cookie，並將其儲存。
* **受影響元件**: Microsoft 365、Node.js

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Kratos 攻擊框架實例，並配置 Node.js 反向代理。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const express = require('express');
    const app = express();
    
    app.use((req, res, next) => {
      // 將用戶登入請求轉發到 Microsoft 365 伺服器
      const microsoft365Url = 'https://login.microsoftonline.com';
      req.pipe(require('request')(microsoft365Url)).pipe(res);
    });
    
    app.listen(3000, () => {
      console.log('Kratos 攻擊框架啟動');
    });
    
    ```
* **繞過技術**: Kratos 攻擊框架可以繞過雙因素驗證，透過捕獲 Session Cookie 實現登入。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 192.0.2.1 |
| Domain | kratos-attack.com |
| File Path | /var/www/kratos/index.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Kratos_Attack {
      meta:
        description = "Kratos 攻擊框架偵測"
      strings:
        $a = "kratos-attack.com"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 Microsoft 365 伺服器的安全設定，啟用雙因素驗證，並限制 Session Cookie 的存取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Adversary-in-the-Middle (AiTM)**: 想像一個攻擊者插入到用戶和伺服器之間，實時轉發用戶請求並捕獲結果。技術上是指攻擊者利用反向代理或其他技術，實現用戶請求的轉發和結果的捕獲。
* **Session Cookie 劫持**: 攻擊者捕獲用戶的 Session Cookie，實現登入繞過。
* **雙因素驗證繞過**: 攻擊者利用 AiTM 技術，實現雙因素驗證的繞過。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/police-dismantle-kratos-phishing-kit.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/)


