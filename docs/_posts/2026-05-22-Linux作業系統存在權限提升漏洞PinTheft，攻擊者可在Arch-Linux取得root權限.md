---
layout: post
title:  "Linux作業系統存在權限提升漏洞PinTheft，攻擊者可在Arch Linux取得root權限"
date:   2026-05-22 08:52:25 +0000
categories: [security]
severity: high
---

# 🔥 解析 Linux 核心 PinTheft 漏洞：零複製傳送路徑的攻防技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 7.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: Zero-Copy, RDS (Reliable Datagram Sockets), io_uring

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: PinTheft 漏洞出現在 Linux 核心的 RDS 通訊協定中，特別是在零複製傳送路徑。當 `rds_message_zcopy_from_user()` 函數嘗試將使用者的頁面釘選到內核中時，如果過程中出現異常，錯誤的路徑會捨棄已釘選的頁面。然而，在零複製通知器被清除後，散列清單條目及其計數器仍保持有效，導致攻擊者可以竊取頁面引用。
* **攻擊流程圖解**:
  1. 攻擊者發送零複製訊息。
  2. `rds_message_zcopy_from_user()` 嘗試釘選使用者的頁面。
  3. 如果過程中出現異常，錯誤的路徑會捨棄已釘選的頁面。
  4. 零複製通知器被清除，但散列清單條目及其計數器仍保持有效。
  5. 攻擊者可以竊取頁面引用。
* **受影響元件**: Arch Linux 預設部署相關的 RDS 核心模組，因此存在風險。其他發行版如 Fedora 44 也可能受影響。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要有執行 SUID 二進位檔案的權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import os
      import sys
    
      # 建立 io_uring 元件
      uring = io_uring()
    
      # 建立 RDS 連線
      rds = socket.socket(socket.AF_RDS, socket.SOCK_SEQPACKET)
    
      # 發送零複製訊息
      rds.send(uring, b"payload")
    
      # 執行 SUID 二進位檔案
      os.execv("/path/to/suid_binary", ["suid_binary"])
    
    ```
* **繞過技術**: 攻擊者可以使用 io_uring 元件來繞過 WAF 或 EDR 的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | /path/to/suid_binary |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule PinTheft_Detection {
        meta:
          description = "Detect PinTheft exploit"
          author = "Your Name"
        strings:
          $s1 = "io_uring" ascii
          $s2 = "RDS" ascii
        condition:
          all of ($s*)
      }
    
    ```
* **緩解措施**: 更新 Linux 核心到最新版本，停用 RDS 核心模組，如果不需要使用 RDS。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Zero-Copy (零複製)**: 一種技術，允許應用程序直接訪問內核緩衝區，無需複製數據。
* **RDS (Reliable Datagram Sockets)**: 一種 Linux 核心通訊協定，提供可靠的數據報傳輸。
* **io_uring**: 一種 Linux 核心元件，提供高性能的 I/O 操作。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://www.ithome.com.tw/news/176044)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


