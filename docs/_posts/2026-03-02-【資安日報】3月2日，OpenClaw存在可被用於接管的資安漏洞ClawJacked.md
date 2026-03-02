---
layout: post
title:  "【資安日報】3月2日，OpenClaw存在可被用於接管的資安漏洞ClawJacked"
date:   2026-03-02 12:41:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OpenClaw ClawJacked 漏洞：WebSocket 連線挾持與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: WebSocket, JavaScript, 身分驗證請求

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OpenClaw 啟動時建立的本地閘道（gateway）服務，透過 WebSocket 監聽本機（localhost）連線，原本設計目的是讓瀏覽器介面與 OpenClaw 代理溝通。然而，攻擊者可透過惡意網站的 JavaScript 程式碼，嘗試與電腦本機的 WebSocket 建立連線，而瀏覽器的跨來源政策（cross-origin policies）不會阻擋此類連線行為。
* **攻擊流程圖解**:
  1. 攻擊者誘導使用者瀏覽惡意網站。
  2. 惡意網站的 JavaScript 程式碼嘗試與電腦本機的 WebSocket 建立連線。
  3. WebSocket 連線成功後，攻擊者可透過 WebSocket 發送身分驗證請求。
  4. 閘道服務對於來自本機的身分驗證請求，未實施嚴格的速率限制，導致攻擊者可透過瀏覽器在系統背景執行暴力破解，猜出密碼並登入 OpenClaw。
* **受影響元件**: OpenClaw 2026.2.25 版之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要誘導使用者瀏覽惡意網站。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意網站的 JavaScript 程式碼
      var socket = new WebSocket('ws://localhost:8080');
      socket.onopen = function() {
        // 發送身分驗證請求
        socket.send('auth_request');
      };
      socket.onmessage = function(event) {
        // 處理身分驗證回應
        if (event.data === 'auth_success') {
          // 登入 OpenClaw
          socket.send('login_request');
        }
      };
    
    ```
* **繞過技術**: 攻擊者可透過瀏覽器的跨來源政策（cross-origin policies）繞過 WebSocket 連線的限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule OpenClaw_ClawJacked {
        meta:
          description = "OpenClaw ClawJacked 漏洞偵測"
          author = "Your Name"
        strings:
          $ws_connect = "ws://localhost:8080"
        condition:
          $ws_connect
      }
    
    ```
* **緩解措施**: 更新 OpenClaw 至 2026.2.25 版或之後的版本，並實施嚴格的速率限制和身分驗證機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebSocket**: 一種允許網頁瀏覽器和伺服器之間進行全雙工通訊的協議。
* **跨來源政策 (Cross-Origin Policy)**: 一種安全機制，限制網頁瀏覽器可以存取的資源。
* **身分驗證請求 (Authentication Request)**: 一種請求，要求使用者提供身分驗證資訊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174114)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


