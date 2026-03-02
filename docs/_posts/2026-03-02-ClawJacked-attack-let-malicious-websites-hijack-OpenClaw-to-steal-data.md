---
layout: post
title:  "ClawJacked attack let malicious websites hijack OpenClaw to steal data"
date:   2026-03-02 01:25:15 +0000
categories: [security]
severity: high
---

# 🔥 解析 OpenClaw 的 ClawJacked 弱點：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: WebSocket, Brute-Force Attack, Localhost Loopback Connection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: OpenClaw 的 Gateway 服務預設綁定到 localhost，並暴露 WebSocket 介面。由於瀏覽器的跨源政策不會阻止 WebSocket 連接到 localhost，因此惡意網站可以使用 JavaScript 在用戶不知情的情況下連接到本地 Gateway 服務並嘗試進行驗證。
* **攻擊流程圖解**:
  1. 惡意網站使用 JavaScript 打開 WebSocket 連接到本地 OpenClaw Gateway 服務。
  2. 惡意網站嘗試進行驗證，使用 Brute-Force Attack 的方式猜測密碼。
  3. 由於 localhost 的 loopback 連接預設不受限速限制，攻擊者可以在短時間內嘗試大量的密碼組合。
  4. 一旦攻擊者猜測正確的密碼，就可以註冊為受信任的設備，並獲得管理員權限。
* **受影響元件**: OpenClaw 2026.2.26 版本之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要知道受害者正在運行 OpenClaw 服務，並且能夠訪問惡意網站。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 JavaScript Payload
    const socket = new WebSocket('ws://localhost:8080');
    socket.onopen = function() {
      socket.send('login:username,password');
    };
    socket.onmessage = function(event) {
      if (event.data === 'login:success') {
        // 獲得管理員權限，進行後續攻擊
      }
    };
    
    ```
* **繞過技術**: 攻擊者可以使用 WebSocket 連接到 localhost 的 loopback 連接，繞過 OpenClaw 的限速限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 127.0.0.1 |
| Domain | localhost |
| File Path | /var/openclaw/gateway.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OpenClaw_ClawJacked {
      meta:
        description = "Detects OpenClaw ClawJacked attack"
      strings:
        $ws_connect = "ws://localhost:8080"
      condition:
        $ws_connect in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 OpenClaw 到 2026.2.26 版本或以上，並設定 Gateway 服務只允許受信任的連接。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **WebSocket**: 一種允許瀏覽器和伺服器之間進行全雙工通信的協議。
* **Brute-Force Attack**: 一種嘗試使用大量的密碼組合來猜測密碼的攻擊方式。
* **Localhost Loopback Connection**: 一種允許本地主機與自己進行通信的連接方式。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.bleepingcomputer.com/news/security/clawjacked-attack-let-malicious-websites-hijack-openclaw-to-steal-data/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


