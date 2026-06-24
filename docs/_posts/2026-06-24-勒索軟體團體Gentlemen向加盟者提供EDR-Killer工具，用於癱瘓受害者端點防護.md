---
layout: post
title:  "勒索軟體團體Gentlemen向加盟者提供EDR Killer工具，用於癱瘓受害者端點防護"
date:   2026-06-24 08:56:47 +0000
categories: [security]
severity: critical
---

# 🚨 解析勒索軟體即服務（RaaS）團體的EDR Killer工具
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: EDR Killer工具利用存在弱點或惡意的驅動程式，提升權限並停用受害者的EDR防護引擎。這是因為驅動程式沒有正確地檢查用戶輸入的資料，導致了權限提升的漏洞。
* **攻擊流程圖解**: 
  1. 攻擊者將惡意的驅動程式上傳到受害者的系統。
  2. 驅動程式被加載到系統中。
  3. 驅動程式利用存在的弱點提升權限。
  4. 驅動程式停用受害者的EDR防護引擎。
* **受影響元件**: 受影響的元件包括多個版本的Windows操作系統和多個品牌的EDR防護軟體。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者的系統管理權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import ctypes
    
    # 定義惡意的驅動程式
    driver_path = "C:\\\\Windows\\\\System32\\\\drivers\\\\malicious.sys"
    
    # 加載惡意的驅動程式
    ctypes.windll.kernel32.LoadLibraryW(driver_path)
    
    # 執行惡意的驅動程式
    os.system("net start malicious")
    
    ```
    *範例指令*: 使用`curl`下載惡意的驅動程式並加載到系統中。
* **繞過技術**: 攻擊者可以使用`Heap Spraying`技術來繞過EDR防護軟體的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | malicious.com | C:\\\\Windows\\\\System32\\\\drivers\\\\malicious.sys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_driver {
      meta:
        description = "惡意的驅動程式"
        author = "Blue Team"
      strings:
        $s1 = "malicious.sys"
      condition:
        $s1 in (filename)
    }
    
    ```
    或者是具體的**SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=windows_event_log (EventID=7045 AND DriverName="malicious.sys")
    
    ```
* **緩解措施**: 除了更新修補之外，還可以設定EDR防護軟體的規則來阻止惡意的驅動程式被加載。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 想像一塊記憶體空間被填滿了惡意的程式碼。技術上是指攻擊者在記憶體中填充大量的惡意程式碼，以便在執行時能夠繞過安全檢查。
* **Deserialization**: 想像一個物件被序列化成字串，然後被反序列化回物件。技術上是指將資料從字串或其他格式轉換回物件的過程。
* **eBPF**: 想像一個小型的程式碼被執行在Linux核心中。技術上是指一種在Linux核心中執行的小型程式碼，通常用於網路封包過濾和安全檢查。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176855)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


