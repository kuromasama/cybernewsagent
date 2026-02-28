---
layout: post
title:  "ClawJacked Flaw Lets Malicious Sites Hijack Local OpenClaw AI Agents via WebSocket"
date:   2026-02-28 18:23:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OpenClaw 高風險安全漏洞：ClawJacked
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: 遠端代碼執行 (RCE) 和授權繞過
> * **關鍵技術**: WebSocket、JavaScript、Rate Limiting

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OpenClaw 的 WebSocket 伺服器缺乏適當的速率限制機制，允許攻擊者進行暴力破解密碼的攻擊。
* **攻擊流程圖解**:
  1. 攻擊者透過社交工程或其他手段誘導開發者訪問惡意網站。
  2. 惡意網站上的 JavaScript 代碼建立一個 WebSocket 連接到開發者的本地 OpenClaw 伺服器。
  3. JavaScript 代碼進行暴力破解密碼攻擊，直到成功登入。
  4. 登入後，攻擊者可以註冊為信任設備，並獲得對 AI 代理的完整控制權。
* **受影響元件**: OpenClaw 2026.2.25 版本之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道開發者的本地 OpenClaw 伺服器的 WebSocket 連接埠和密碼。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 JavaScript 代碼
    const socket = new WebSocket('ws://localhost:8080');
    socket.onmessage = (event) => {
      if (event.data === '登入成功') {
        // 註冊為信任設備
        socket.send('註冊信任設備');
      }
    };
    socket.onopen = () => {
      // 進行暴力破解密碼攻擊
      for (let i = 0; i < 10000; i++) {
        socket.send(`登入:${i}`);
      }
    };
    
    ```
* **繞過技術**: 攻擊者可以使用 WebSocket 連接埠的代理伺服器來繞過防火牆或入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 91.92.242.30 |
| Domain | openclawcli.vercel.app |
| File Path | /usr/local/openclaw/logs |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OpenClaw_ClawJacked {
      meta:
        description = "OpenClaw ClawJacked 攻擊"
        author = "Your Name"
      strings:
        $a = "ws://localhost:8080"
        $b = "登入成功"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新 OpenClaw 至 2026.2.25 版本或以上，並啟用速率限制機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebSocket**: 一種允許網頁瀏覽器和伺服器之間進行全雙工通訊的協議。
* **Rate Limiting**: 一種用於限制網路請求速率的技術，防止暴力破解密碼攻擊。
* **JavaScript**: 一種用於網頁瀏覽器的腳本語言，常用於網頁開發。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/clawjacked-flaw-lets-malicious-sites.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


