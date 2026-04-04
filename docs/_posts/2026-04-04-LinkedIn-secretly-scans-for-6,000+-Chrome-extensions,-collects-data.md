---
layout: post
title:  "LinkedIn secretly scans for 6,000+ Chrome extensions, collects data"
date:   2026-04-04 18:32:37 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 LinkedIn 的隱藏 JavaScript 腳本：瀏覽器擴充功能掃描與設備資料收集

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: JavaScript Fingerprinting, Browser Extension Detection, Device Data Collection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LinkedIn 的網站注入了一個隱藏的 JavaScript 腳本，該腳本掃描訪客的瀏覽器擴充功能，並收集設備資料。這個腳本使用了一種稱為「JavaScript Fingerprinting」的技術，通過檢查瀏覽器的特徵（例如 CPU 核心數、可用記憶體、螢幕解析度等）來收集設備資料。
* **攻擊流程圖解**:
	1. 訪客訪問 LinkedIn 網站
	2. LinkedIn 網站注入隱藏的 JavaScript 腳本
	3. 腳本掃描訪客的瀏覽器擴充功能
	4. 腳本收集設備資料（例如 CPU 核心數、可用記憶體、螢幕解析度等）
* **受影響元件**: LinkedIn 網站、Google Chrome 瀏覽器

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 訪客必須訪問 LinkedIn 網站，並且使用 Google Chrome 瀏覽器
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 JavaScript 腳本
    function detectExtensions() {
      const extensions = [];
      for (const extension of chrome.extensions.getAll()) {
        if (extension.name === '某個擴充功能') {
          extensions.push(extension);
        }
      }
      return extensions;
    }
    
    function collectDeviceData() {
      const deviceData = {
        cpuCores: navigator.hardwareConcurrency,
        availableMemory: navigator.deviceMemory,
        screenResolution: `${screen.width}x${screen.height}`,
      };
      return deviceData;
    }
    
    const extensions = detectExtensions();
    const deviceData = collectDeviceData();
    // 將收集到的資料傳送到伺服器
    fetch('/collect-data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ extensions, deviceData }),
    });
    
    ```
* **繞過技術**: 可以使用瀏覽器擴充功能（例如 uBlock Origin）來阻止 LinkedIn 網站注入隱藏的 JavaScript 腳本

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | linkedin.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LinkedIn_Fingerprinting {
      meta:
        description = "LinkedIn Fingerprinting"
        author = "Your Name"
      strings:
        $js_script = "detectExtensions" wide
      condition:
        $js_script
    }
    
    ```
* **緩解措施**: 可以使用瀏覽器擴充功能（例如 uBlock Origin）來阻止 LinkedIn 網站注入隱藏的 JavaScript 腳本。另外，可以設定瀏覽器的隱私設定，以限制 LinkedIn 網站收集設備資料。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Fingerprinting**: 一種技術，通過檢查瀏覽器的特徵（例如 CPU 核心數、可用記憶體、螢幕解析度等）來收集設備資料。
* **Browser Extension Detection**: 一種技術，通過檢查瀏覽器的擴充功能來收集設備資料。
* **Device Data Collection**: 一種技術，通過收集設備資料（例如 CPU 核心數、可用記憶體、螢幕解析度等）來進行指紋識別。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/linkedin-secretly-scans-for-6-000-plus-chrome-extensions-collects-data/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


