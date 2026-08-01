---
layout: post
title:  "Adobe Campaign Classic CVSS 10.0 Flaw Could Run Code Without User Interaction"
date:   2026-08-01 08:07:53 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Adobe Campaign Classic 的任意代碼執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 10.0)
> * **受駭指標**: 任意代碼執行 (RCE)
> * **關鍵技術**: Incorrect Authorization, SQL Injection, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Adobe Campaign Classic 中的授權機制存在缺陷，導致攻擊者可以在不需要任何用戶交互的情況下執行任意代碼。
* **攻擊流程圖解**: 
    1. 攻擊者發送精心構造的請求到 Adobe Campaign Classic 伺服器。
    2. 伺服器未能正確驗證用戶身份和授權。
    3. 攻擊者利用此漏洞執行任意代碼。
* **受影響元件**: Adobe Campaign Classic v7: 7.4.3 build 9398 (Windows 和 Linux)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 Adobe Campaign Classic 伺服器的 URL 和相關的 API 端點。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義攻擊 payload
    payload = {
        # 精心構造的請求資料
    }
    
    # 發送請求到 Adobe Campaign Classic 伺服器
    response = requests.post('https://example.com/adobe-campaign-classic/api/endpoint', json=payload)
    
    # 驗證攻擊是否成功
    if response.status_code == 200:
        print('攻擊成功')
    else:
        print('攻擊失敗')
    
    ```
    *範例指令*: 使用 `curl` 工具發送請求

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"key": "value"}' https://example.com/adobe-campaign-classic/api/endpoint

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用編碼或加密的 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Adobe_Campaign_Classic_Vulnerability {
        meta:
            description = "Adobe Campaign Classic 任意代碼執行漏洞"
            author = "Your Name"
        strings:
            $a = "精心構造的請求資料"
        condition:
            $a
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)

```

sql
index=adobe_campaign_classic sourcetype=api_endpoint | search "精心構造的請求資料"

```
* **緩解措施**: 更新 Adobe Campaign Classic 至最新版本 (v7: 7.4.3 build 9398 或以上)。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Incorrect Authorization (授權錯誤)**: 想像兩個用戶同時存取同一資源，但系統未能正確驗證用戶身份和授權。技術上是指系統未能正確驗證用戶身份和授權，導致攻擊者可以執行任意代碼。
* **SQL Injection (SQL 注入)**: 想像攻擊者可以注入惡意的 SQL 代碼到系統的資料庫中。技術上是指攻擊者可以注入惡意的 SQL 代碼到系統的資料庫中，導致系統執行任意 SQL 代碼。
* **Deserialization (反序列化)**: 想像系統可以將資料從序列化的格式轉換回原始的格式。技術上是指系統可以將資料從序列化的格式轉換回原始的格式，可能導致攻擊者可以執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/adobe-campaign-classic-cvss-100-flaw.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


