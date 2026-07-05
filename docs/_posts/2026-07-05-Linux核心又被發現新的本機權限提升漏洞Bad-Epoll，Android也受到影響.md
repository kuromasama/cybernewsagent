---
layout: post
title:  "Linux核心又被發現新的本機權限提升漏洞Bad Epoll，Android也受到影響"
date:   2026-07-05 02:27:04 +0000
categories: [security]
severity: high
---

# 🔥 解析 Linux 核心的 Bad Epoll 本地權限提升漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：7.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Use-After-Free`, `Race Condition`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Bad Epoll 漏洞是由於 Linux 核心的 epoll 子系統中存在競態條件（race condition），導致記憶體釋放後再存取利用（Use-After-Free，UAF）。這個漏洞是在 Linux 核心 6.4 版引入的。
* **攻擊流程圖解**: 
  1. 攻擊者創建一個 epoll 物件。
  2. 攻擊者將一個檔案描述符（file descriptor）添加到 epoll 物件中。
  3. 攻擊者釋放檔案描述符。
  4. 攻擊者觸發 epoll 物件的事件處理函數。
  5. 如果競態條件成立，epoll 物件會存取已釋放的檔案描述符，導致 UAF。
* **受影響元件**: Linux 核心 6.4 版或更新版本，包括 Linux 桌面系統、伺服器和 Android。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在目標系統上具有無特權的使用者權限。
* **Payload 建構邏輯**:

    ```
    
    c
      // 範例 Payload 結構
      struct epoll_event {
        uint32_t events;
        void *data;
      };
    
      // 創建 epoll 物件
      int epoll_fd = epoll_create1(0);
    
      // 添加檔案描述符到 epoll 物件中
      struct epoll_event event;
      event.events = EPOLLIN;
      event.data = NULL;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
    
      // 釋放檔案描述符
      close(fd);
    
      // 觸發 epoll 物件的事件處理函數
      epoll_wait(epoll_fd, &event, 1, -1);
    
    ```
* **繞過技術**: 目前沒有公開的繞過技術。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Bad_Epoll {
        meta:
          description = "Detects Bad Epoll exploit"
          author = "Your Name"
        strings:
          $epoll_create = { 0x?? 0x?? 0x?? 0x?? 0x?? 0x?? 0x?? 0x?? }
        condition:
          $epoll_create at entry0
      }
    
    ```
* **緩解措施**: 更新 Linux 核心到最新版本，或者套用修補程式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Use-After-Free (UAF)**: 想像你有一個指標指向一塊記憶體，然後你釋放了這塊記憶體，但是你仍然使用這個指標來存取這塊記憶體。技術上是指程式在釋放記憶體後仍然使用這塊記憶體，導致數據不一致或邏輯錯誤。
* **Race Condition (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 核心的網路封包過濾機制，允許用戶空間程式碼在內核中執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177088)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


