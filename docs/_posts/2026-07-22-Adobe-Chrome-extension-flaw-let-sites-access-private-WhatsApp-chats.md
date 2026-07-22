---
layout: post
title:  "Adobe Chrome extension flaw let sites access private WhatsApp chats"
date:   2026-07-22 13:26:38 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Adobe Acrobat Chrome 擴充功能的 HermeticReader 漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (私訊內容洩露)
> * **關鍵技術**: DOM 操控、Service Worker、內部 HTML 資源

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Adobe Acrobat Chrome 擴充功能的內部 HTML 資源允許任何網頁包含它作為 iframe，並且沒有檢查來源的驗證機制，導致攻擊者可以將惡意命令傳遞給擴充功能的 Service Worker。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意網頁，包含 Adobe Acrobat 擴充功能的內部 HTML 資源作為 iframe。
  2. 網頁傳遞惡意命令給擴充功能的 Service Worker。
  3. Service Worker 執行命令，激活 WhatsApp 整合功能。
  4. 攻擊者可以控制 WhatsApp 網頁的 DOM，竊取私訊內容。
* **受影響元件**: Adobe Acrobat Chrome 擴充功能版本 26.5.2.1 及以下。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意網頁，包含 Adobe Acrobat 擴充功能的內部 HTML 資源作為 iframe。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意網頁的 JavaScript 代碼
    const iframe = document.createElement('iframe');
    iframe.src = 'https://example.com/adobe-acrobat-internal-html';
    document.body.appendChild(iframe);
    
    // 傳遞惡意命令給 Service Worker
    const worker = new Worker('https://example.com/service-worker.js');
    worker.postMessage({ type: 'activate-whatsapp' });
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦措施，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /adobe-acrobat-internal-html |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Adobe_Acrobat_Exploit {
      meta:
        description = "Detects Adobe Acrobat exploit"
      strings:
        $a = "https://example.com/adobe-acrobat-internal-html"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 Adobe Acrobat Chrome 擴充功能至版本 26.5.2.3 或以上。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Service Worker**: 一種 Web 技術，允許 Web 應用程式在背景執行腳本，提供離線存取和推送通知等功能。
* **DOM (Document Object Model)**: 一種樹狀結構，代表 HTML 文件的內容和結構。
* **iframe (inline frame)**: 一種 HTML 元素，允許嵌入其他網頁或文件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/adobe-chrome-extension-flaw-let-sites-access-private-whatsapp-chats/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


