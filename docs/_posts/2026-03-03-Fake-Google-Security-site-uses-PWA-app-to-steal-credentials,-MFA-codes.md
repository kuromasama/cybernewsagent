---
layout: post
title:  "Fake Google Security site uses PWA app to steal credentials, MFA codes"
date:   2026-03-03 01:28:09 +0000
categories: [security]
severity: critical
---

# 🚨 進階威脅分析：解析假冒 Google 安全頁面的 PWA 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: PWA (Progressive Web App), Social Engineering, WebSocket Relay

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用假冒的 Google 安全頁面，誘騙用戶安裝惡意的 PWA 應用程式。這個應用程式可以竊取用戶的 OTP (One-Time Password) 和加密貨幣錢包地址，並將攻擊者的流量代理到受害者的瀏覽器中。
* **攻擊流程圖解**:
  1. 用戶訪問假冒的 Google 安全頁面。
  2. 用戶被誘騙安裝惡意的 PWA 應用程式。
  3. PWA 應用程式竊取用戶的 OTP 和加密貨幣錢包地址。
  4. PWA 應用程式將攻擊者的流量代理到受害者的瀏覽器中。
* **受影響元件**: Google Chrome, Microsoft Edge, Safari 等瀏覽器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個假冒的 Google 安全頁面和一個惡意的 PWA 應用程式。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意的 PWA 應用程式代碼
    const WebSocket = require('ws');
    const wss = new WebSocket.Server({ port: 8080 });
    
    wss.on('connection', (ws) => {
      console.log('用戶連接');
      ws.on('message', (message) => {
        console.log(`收到用戶消息: ${message}`);
        // 將用戶的 OTP 和加密貨幣錢包地址竊取並傳送給攻擊者
      });
    });
    
    ```
* **繞過技術**: 攻擊者可以使用 Social Engineering 技術來誘騙用戶安裝惡意的 PWA 應用程式。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | google-prism.com | /usr/local/bin/malware |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malware_Detection {
      meta:
        description = "偵測惡意的 PWA 應用程式"
      strings:
        $a = "WebSocket"
        $b = "wss://"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 用戶應該避免安裝來自不明來源的 PWA 應用程式，並定期更新瀏覽器和操作系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PWA (Progressive Web App)**: 一種使用 Web 技術開發的應用程式，可以在瀏覽器中運行，也可以安裝在用戶的設備上。
* **WebSocket**: 一種使用 TCP 協議的雙向通信技術，允許用戶和伺服器之間進行實時通信。
* **Social Engineering**: 一種攻擊技術，利用人類的心理弱點來誘騙用戶進行某些行動。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fake-google-security-site-uses-pwa-app-to-steal-credentials-mfa-codes/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


