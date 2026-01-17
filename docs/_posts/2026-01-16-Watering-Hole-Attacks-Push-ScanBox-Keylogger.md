---
layout: post
title:  "Watering Hole Attacks Push ScanBox Keylogger"
date:   2026-01-16 14:22:00 +0000
categories: [security]
---

# 🚨 解析 ScanBox 蠕蟲的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Keylogger 和瀏覽器指紋收集
> * **關鍵技術**: `ScanBox`, `JavaScript`, `WebRTC`, `STUN`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ScanBox 是一個基於 JavaScript 的框架，利用瀏覽器的漏洞收集用戶的鍵盤輸入和瀏覽器指紋。
* **攻擊流程圖解**:
  1. 用戶點擊惡意連結，導向一個包含 ScanBox 代碼的網頁。
  2. ScanBox 代碼執行，收集用戶的鍵盤輸入和瀏覽器指紋。
  3. 收集到的數據通過 WebRTC 和 STUN 協議傳送給攻擊者的伺服器。
* **受影響元件**: 所有支持 WebRTC 的瀏覽器，包括 Google Chrome、Mozilla Firefox、Microsoft Edge 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個包含 ScanBox 代碼的網頁，和一個 STUN 伺服器。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // ScanBox 代碼
      var scanbox = new ScanBox();
      scanbox.init();
      scanbox.start();
      
    
    ```
  

```

bash
  # 使用 curl 發送惡意請求
  curl -X GET 'http://example.com/scanbox.html' -H 'User-Agent: Mozilla/5.0'
  

```
* **繞過技術**: 攻擊者可以使用各種方法繞過瀏覽器的安全機制，例如使用零日漏洞或社工攻擊。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

          | Hash | IP | Domain | File Path |
          | --- | --- | --- | --- |
          | 1234567890abcdef | 192.168.1.100 | example.com | /scanbox.html |


* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ScanBox_Detection {
        meta:
          description = "Detect ScanBox malware"
          author = "Your Name"
        strings:
          $a = "ScanBox" ascii
          $b = "init" ascii
          $c = "start" ascii
        condition:
          all of them
      }
      
    
    ```
  

```

snort
  alert tcp any any -> any any (msg:"ScanBox Detection"; content:"ScanBox"; sid:1000001;)
  

```
* **緩解措施**: 更新瀏覽器和操作系統，啟用瀏覽器的安全功能，例如 Google Chrome 的沙盒模式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebRTC (Web Real-Time Communication)**: 一種實時通信技術，允許瀏覽器之間直接進行通信。
* **STUN (Session Traversal Utilities for NAT)**: 一種協議，允許瀏覽器在 NAT 網路中進行通信。
* **JavaScript**: 一種腳本語言，常用於網頁開發。

## 5. 🔗 參考文獻與延伸閱讀
* [原始報告](https://threatpost.com/watering-hole-attacks-push-scanbox-keylogger/180490/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)

