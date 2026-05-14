---
layout: post
title:  "Stealer Backdoor Found in 3 Node-IPC Versions Targeting Developer Secrets"
date:   2026-05-14 19:38:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Node-IPC 惡意活動：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Stealer/Backdoor
> * **關鍵技術**: Obfuscated Payload, DNS Exfiltration, SHA-256 Fingerprint Check

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Node-IPC 套件的維護者帳戶被攻擊者控制，導致發布了惡意版本（9.1.6、9.2.3、12.0.1）。
* **攻擊流程圖解**:
  1. 使用者安裝惡意版本的 Node-IPC。
  2. 惡意代碼在 `node-ipc.cjs` 文件末尾追加了一個 IIFE（Immediately Invoked Function Expression）。
  3. IIFE 執行時，進行 SHA-256 指紋檢查，若通過則繼續執行惡意代碼。
  4. 惡意代碼枚舉和讀取本地文件，壓縮和分塊收集的數據。
  5. 使用 DNS 進行數據外泄，將壓縮的數據發送到 C2 伺服器。
* **受影響元件**: Node-IPC 套件版本 9.1.6、9.2.3、12.0.1。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Node-IPC 套件的維護者帳戶被攻擊者控制。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload 結構
    const payload = {
      'type': 'stealer',
      'data': {
        'files': [],
        'credentials': []
      }
    };
    
    // 將收集的數據添加到 payload 中
    payload.data.files.push('file1.txt');
    payload.data.credentials.push('username:password');
    
    // 壓縮和分塊 payload
    const compressedPayload = compress(payload);
    const chunkedPayload = chunk(compressedPayload);
    
    // 使用 DNS 進行數據外泄
    sendDnsQuery(chunkedPayload);
    
    ```
* **繞過技術**: 使用 DNS 進行數據外泄，可以繞過一些安全控制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 1.1.1.1 | sh.azurestaticprovider.net | node-ipc.cjs |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Node_IPC_Malicious {
      meta:
        description = "Detects malicious Node-IPC activity"
      strings:
        $payload = { 61 73 74 65 61 6c 65 72 }
      condition:
        $payload at 0
    }
    
    ```
* **緩解措施**:
 1. 移除惡意版本的 Node-IPC 套件。
 2. 重新安裝乾淨版本的 Node-IPC 套件（9.2.1 和 12.0.0）。
 3. 旋轉憑證和密碼。
 4. 審計 npm 發布活動。
 5. 審計雲端日誌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SHA-256 指紋檢查**: 一種使用 SHA-256 演算法進行數據指紋檢查的技術，用于驗證數據的完整性和真實性。
* **DNS Exfiltration**: 一種使用 DNS 協議進行數據外泄的技術，攻擊者可以使用 DNS 查詢將數據發送到 C2 伺服器。
* **IIFE (Immediately Invoked Function Expression)**: 一種 JavaScript 技術，用于立即執行函數表達式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/stealer-backdoor-found-in-3-node-ipc.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1041/)


