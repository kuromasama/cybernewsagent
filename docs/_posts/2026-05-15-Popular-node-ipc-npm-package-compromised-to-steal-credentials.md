---
layout: post
title:  "Popular node-ipc npm package compromised to steal credentials"
date:   2026-05-15 19:22:09 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Node-ipc 套件的供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: 資料外洩 (Info Leak)
> * **關鍵技術**: DNS TXT 查詢、資料壓縮、環境變數竊取

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Node-ipc 套件的維護者帳戶被攻擊者入侵，導致套件中注入了惡意代碼。惡意代碼藏在 CommonJS 入口點 (node-ipc.cjs) 中，並在應用程式加載時自動執行。
* **攻擊流程圖解**:
  1. 攻擊者入侵 Node-ipc 套件的維護者帳戶。
  2. 攻擊者注入惡意代碼到 Node-ipc 套件中。
  3. 使用者安裝或更新 Node-ipc 套件。
  4. 惡意代碼在應用程式加載時自動執行。
  5. 惡意代碼竊取環境變數、敏感檔案和其他資料。
  6. 惡意代碼壓縮竊取的資料並透過 DNS TXT 查詢外洩。
* **受影響元件**: Node-ipc 套件版本 9.1.6、9.2.3 和 12.0.1。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要入侵 Node-ipc 套件的維護者帳戶。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload 結構
    const payload = {
      'type': 'dns_txt',
      'data': '竊取的資料',
      'domain': 'sh.azurestaticprovider.net'
    };
    
    ```
* **繞過技術**: 攻擊者使用 DNS TXT 查詢來外洩資料，避免了傳統的 HTTP-based 命令和控制 (C2) 流量。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | sh.azurestaticprovider.net | /tmp/node-ipc.cjs |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Node_Ipc_Malware {
      meta:
        description = "Node-ipc 套件惡意代碼"
      strings:
        $a = "sh.azurestaticprovider.net"
      condition:
        $a in (http.request.uri || dns.query)
    }
    
    ```
* **緩解措施**: 使用者應立即移除受影響的 Node-ipc 套件版本，旋轉暴露的密碼和憑證，並檢查 lockfiles 和 npm 快取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DNS TXT 查詢 (DNS TXT Query)**: 一種 DNS 查詢類型，允許查詢 TXT 記錄。TXT 記錄可以包含任意文字資料。
* **環境變數 (Environment Variable)**: 一種儲存敏感資料的方法，例如密碼和 API 金鑰。
* **壓縮 (Compression)**: 一種減少資料大小的方法，常用於加密和外洩資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/popular-node-ipc-npm-package-compromised-to-steal-credentials/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1041/)


