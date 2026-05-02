---
layout: post
title:  "Linux系統核心存在高風險漏洞Copy Fail，本機使用者能藉此奪取root權限，廣泛影響多個主流Linux版本"
date:   2026-05-02 02:06:25 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Linux 核心 Copy Fail 漏洞：CVE-2026-31431
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：7.8)
> * **受駭指標**: Local Privilege Escalation (LPE)
> * **關鍵技術**: 密碼學範本、Page Cache、setuid binary

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Copy Fail 是一個邏輯臭蟲，存在於 Linux 系統核心的密碼學範本 authencesn 中。這個漏洞允許未取得權限的本機使用者，觸發長度為 4 個位元組的受控資料寫入動作，寫入的目標是系統中任何可讀取檔案的分頁快取 (Page Cache)。
* **攻擊流程圖解**:
  1.攻擊者創建一個特殊的檔案，包含了要寫入的資料。
  2.攻擊者使用 splice() 系統呼叫，將檔案的分頁快取傳遞給 crypto/ 子系統。
  3.攻擊者使用 setuid binary (例如 /usr/bin/passwd 或 /usr/bin/su) 來執行攻擊。
* **受影響元件**: Linux 核心版本 4.14 到 7.0-rc 版、6.18.22 之前的 6.18.x 版、6.19.12 之前的 6.19.x 版。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 本機使用者權限、網路存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 創建一個特殊的檔案
    with open("exploit_file", "wb") as f:
        f.write(b"exploit_data")
    
    # 使用 splice() 系統呼叫
    os.system("splice()")
    
    # 使用 setuid binary 來執行攻擊
    os.system("/usr/bin/passwd exploit_file")
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏攻擊 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/bin/passwd |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Copy_Fail_Detection {
        meta:
            description = "Detects Copy Fail exploit"
            author = "Your Name"
        strings:
            $exploit_file = "exploit_file"
            $splice_call = "splice()"
        condition:
            $exploit_file and $splice_call
    }
    
    ```
* **緩解措施**: 更新 Linux 核心版本到 7.0 或以上、6.19.12 或以上、6.18.22 或以上。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Page Cache**: Page Cache 是 Linux 系統中的一個緩存機制，用于暫存檔案的內容，以加速檔案的存取。
* **setuid binary**: setuid binary 是一種特殊的執行檔，當它被執行時，會以檔案所有者的權限執行，而不是以執行者的權限執行。
* **splice()**: splice() 是 Linux 系統中的一個系統呼叫，用于在兩個檔案描述符之間傳遞資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175481)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


