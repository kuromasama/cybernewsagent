---
layout: post
title:  "LangGraph Flaw Chain Exposes Self-Hosted AI Agents to Remote Code Execution"
date:   2026-06-12 09:59:41 +0000
categories: [security]
severity: critical
---

# 🚨 解析 LangGraph 框架的安全漏洞：利用 SQL 注入和反序列化漏洞實現遠程代碼執行

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：7.3)
> * **受駭指標**: 遠程代碼執行 (RCE)
> * **關鍵技術**: SQL 注入、反序列化、msgpack

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LangGraph 框架的 SQLite checkpoint 實現中存在 SQL 注入漏洞，允許攻擊者操控 SQL 查詢通過元數據篩選鍵。
* **攻擊流程圖解**:
  1. 攻擊者準備一個 msgpackayload，包含執行任意代碼的指令。
  2. 攻擊者發送一個惡意的篩選參數，利用 SQL 注入漏洞返回一個假的 checkpoint 列到數據庫查詢結果中，其中 checkpoint 欄包含攻擊者控制的序列化數據。
  3. 當應用程序處理查詢結果時，它反序列化惡意的 checkpoint BLOB。
  4. 攻擊者利用不安全的反序列化漏洞執行自己的 payload，從而實現遠程代碼執行。
* **受影響元件**: LangGraph 框架的 SQLite checkpoint 實現（版本號：langgraph-checkpoint-sqlite < 3.0.1）和 LangGraph 框架（版本號：langgraph < 1.0.10）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限訪問 LangGraph 框架的 get_state_history() 端點。
* **Payload 建構邏輯**:

    ```
    
    python
    import msgpack
    
    # 建構 payload
    payload = {
        'type': 'execute',
        'code': 'import os; os.system("echo Hello World!")'
    }
    
    # 將 payload 序列化為 msgpack
    msgpack_payload = msgpack.packb(payload)
    
    # 將 msgpack_payload 輸入到惡意的篩選參數中
    filter_param = "SELECT * FROM checkpoint WHERE metadata LIKE '%{}%'".format(msgpack_payload)
    
    ```
* **範例指令**: 使用 `curl` 工具發送惡意的篩選參數：

```

bash
curl -X GET 'http://example.com/get_state_history?filter={}' -H 'Content-Type: application/json'

```
* **繞過技術**: 如果 WAF 或 EDR 存在，可以嘗試使用 Base64 編碼或其他編碼方式來繞過檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/www/html/get_state_history.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LangGraph_SQL_Injection {
      meta:
        description = "Detects SQL injection attacks against LangGraph"
        author = "Your Name"
      strings:
        $s1 = "SELECT * FROM checkpoint WHERE metadata LIKE '%{}%'"
      condition:
        $s1 in (http.request.uri.query or http.request.uri.path)
    }
    
    ```
* **緩解措施**:
  1. 更新 LangGraph 框架到最新版本。
  2. 實現篩選參數的驗證和過濾。
  3. 啟用 WAF 或 EDR 來檢測和阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SQL 注入 (SQL Injection)**: 想像一個攻擊者可以操控 SQL 查詢的參數，從而實現任意代碼執行。技術上是指攻擊者可以注入惡意的 SQL 代碼到應用程序的 SQL 查詢中。
* **反序列化 (Deserialization)**: 想像一個攻擊者可以操控序列化的數據，從而實現任意代碼執行。技術上是指攻擊者可以反序列化惡意的數據到應用程序中。
* **msgpack**: 一種二進制序列化格式，常用於 Web 開發中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/langgraph-flaw-chain-exposes-self.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


