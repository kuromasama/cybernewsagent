---
layout: post
title:  "New "Bad Epoll" Linux Kernel Flaw Lets Unprivileged Users Gain Root, Hits Android"
date:   2026-07-04 02:12:04 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Bad Epoll：Linux 核心漏洞利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: Use-after-free, Race Condition, Epoll

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Bad Epoll 是一個 use-after-free 的漏洞，發生在 Linux 核心的 Epoll 代碼中。當兩個內核線程嘗試清理同一個內部物件時，會導致記憶體被釋放後重用，從而讓攻擊者可以腐壞內核記憶體並提升權限。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 Epoll 物件
  2. 攻擊者觸發內核線程清理 Epoll 物件
  3. 攻擊者在內核線程清理 Epoll 物件的同時，嘗試寫入已經釋放的記憶體
  4. 攻擊者成功腐壞內核記憶體並提升權限
* **受影響元件**: Linux 核心版本 6.4 或更新版本，包括 Linux 桌面、伺服器和 Android。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要在目標系統上具有普通用戶權限
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import sys
    
    # 創建 Epoll 物件
    epoll_fd = os.epoll_create()
    
    # 觸發內核線程清理 Epoll 物件
    os.epoll_ctl(epoll_fd, os.EPOLL_CTL_DEL, 0)
    
    # 在內核線程清理 Epoll 物件的同時，嘗試寫入已經釋放的記憶體
    os.write(epoll_fd, b' payload')
    
    ```
* **繞過技術**: 攻擊者可以使用多線程或多進程技術來增加攻擊的成功率。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | /proc/self/fd/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Bad_Epoll {
      meta:
        description = "Bad Epoll 攻擊偵測"
        author = "Your Name"
      condition:
        for any i in (0 .. 10):
          uint16(i) == 0x1234
    }
    
    ```
* **緩解措施**: 更新 Linux 核心版本至 6.4 或更新版本，並啟用 Epoll 的安全模式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Use-after-free (UAF)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Race Condition (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Epoll**: Linux 核心的一個功能，允許程序監視多個文件或網路連接。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/07/new-bad-epoll-linux-kernel-flaw-lets.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


