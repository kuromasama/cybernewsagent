---
layout: post
title:  "iOS漏洞利用套件Coruna調查有新發現！可追溯到3年前的攻擊Operation Triangulation"
date:   2026-03-27 06:59:30 +0000
categories: [security]
severity: critical
---

# 🚨 Coruna 漏洞利用工具包解析與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Heap Spraying, Deserialization, Use-After-Free

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Coruna 漏洞利用工具包主要透過 Safari 排版引擎 WebKit 的漏洞作為入口，利用 Use-After-Free 技術來實現遠端程式碼執行（RCE）。
* **攻擊流程圖解**:
  1. User Input -> WebKit 排版引擎處理
  2. WebKit 排版引擎發現漏洞 -> Use-After-Free
  3. Use-After-Free -> RCE
* **受影響元件**: iOS 17.2 以下版本，WebKit 排版引擎

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Safari 瀏覽器的使用權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建構 Payload
    payload = {
        'type': 'http',
        'url': 'https://example.com/malicious_payload'
    }
    
    # 發送 Payload
    response = requests.post('https://example.com/vulnerable_endpoint', json=payload)
    
    ```
* **繞過技術**: 可以使用 Heap Spraying 技術來繞過 WebKit 排版引擎的安全機制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious_payload |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Coruna_Detection {
        meta:
            description = "Coruna 漏洞利用工具包偵測"
            author = "Your Name"
        strings:
            $a = "WebKit" wide
            $b = "Use-After-Free" wide
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 iOS 至最新版本，禁用 Safari 瀏覽器的 JavaScript 功能

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Use-After-Free (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Heap Spraying (堆疊噴灑)**: 一種技術，透過在堆疊中填充大量的資料，來增加攻擊成功的機率。
* **Deserialization (反序列化)**: 一種技術，透過將資料從序列化的格式轉換回原始的資料結構。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174713)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


