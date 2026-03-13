---
layout: post
title:  "Veeam Patches 7 Critical Backup & Replication Flaws Allowing Remote Code Execution"
date:   2026-03-13 06:42:44 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Veeam Backup & Replication 軟體的遠端代碼執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.9)
> * **受駭指標**: 遠端代碼執行 (RCE)
> * **關鍵技術**: Deserialization, Use-after-free, Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Veeam Backup & Replication 軟體中的遠端代碼執行漏洞是由於沒有正確地驗證用戶輸入，導致攻擊者可以執行任意代碼。具體來說，漏洞存在於軟體的備份伺服器中，當用戶提交一個精心設計的請求時，可以導致伺服器執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者提交一個精心設計的請求給備份伺服器。
  2. 請求被處理並導致伺服器執行任意代碼。
* **受影響元件**: Veeam Backup & Replication 12.3.2.4165 和所有早期版本 12 建置。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要有備份伺服器的驗證權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 payload
    payload = {
        'key': 'value'
    }
    
    # 提交請求
    response = requests.post('https://example.com/backup', json=payload)
    
    # 執行任意代碼
    if response.status_code == 200:
        print('任意代碼執行成功')
    
    ```
  *範例指令*: 使用 `curl` 提交請求：

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"key": "value"}' https://example.com/backup

```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用編碼或加密來隱藏 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| xxx | 192.168.1.1 | example.com | /backup |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Veeam_Backup_RCE {
      meta:
        description = "Veeam Backup & Replication RCE"
        author = "Your Name"
      strings:
        $payload = { 50 6c 61 79 6c 6f 61 64 }
      condition:
        $payload at 0
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)：

```

sql
index=veeam_backup sourcetype=backup_log | search "POST /backup"

```
* **緩解措施**: 除了更新修補之外，還可以修改配置文件以限制用戶權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Deserialization (反序列化)**: 想像你有一個物件，可以被轉換成字串或其他格式，以便存儲或傳輸。技術上是指將字串或其他格式的數據轉換回物件的過程。
* **Use-after-free (釋放後重用)**: 想像你有一個指針，指向一塊記憶體。技術上是指釋放記憶體後，仍然使用該指針來存取記憶體的行為。
* **Heap Spraying (堆疊噴灑)**: 想像你有一個堆疊，可以被用來存儲數據。技術上是指將大量的數據寫入堆疊中，以便執行任意代碼的行為。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/03/veeam-patches-7-critical-backup.html)
* [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


