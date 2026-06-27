---
layout: post
title:  "Linux存在新的本機權限提升漏洞pedit COW，搭配5.18版至 7.1-rc6版核心的系統均可能受影響"
date:   2026-06-27 19:09:27 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Linux 核心流量控制子系統漏洞：CVE-2026-46331
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Copy-on-Write`, `tcf_pedit_act`, `skb_ensure_writable`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Linux 核心的流量控制基礎架構 (`net/sched`) 中的 `act_pedit` 動作內部的寫入時複製 (`copy-on-write`, COW) 機制有不當的實作。具體來說，`tcf_pedit_act` 函式具有資安漏洞，Linux 核心會在反覆執行編輯金鑰的工作之前，嘗試對 `skb_ensure_writable` 函式計算安全的寫入時複製範圍。然而，這項計算作業本身存在一個致命缺陷：無法考量到因多個分類金鑰而新增的標頭偏移量。
* **攻擊流程圖解**:
  1. 攻擊者發送精心設計的封包，觸發 `tcf_pedit_act` 函式。
  2. `tcf_pedit_act` 函式嘗試計算安全的寫入時複製範圍，但因為缺陷而導致越界寫入。
  3. 攻擊者利用越界寫入，修改共享的頁面快取記憶體，繞過安全控制，獲得 root 權限。
* **受影響元件**: Linux 核心版本 5.18 至 7.1-rc6，包括 Red Hat Enterprise Linux 8 至 10 版、Ubuntu、Debian、SUSE、Oracle Linux、Amazon Linux、CloudLinux。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在目標系統上具有普通使用者權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 建立 socket 連接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("目標 IP", 80))
    
    # 發送精心設計的封包
    payload = b"..."
    sock.send(payload)
    
    # 利用越界寫入，修改共享的頁面快取記憶體
    # ...
    
    ```
* **繞過技術**: 攻擊者可以利用 `tcf_pedit_act` 函式的缺陷，繞過安全控制，獲得 root 權限。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Linux_CVE_2026_46331 {
      meta:
        description = "Linux CVE-2026-46331"
        author = "..."
      strings:
        $a = { ... } // tcf_pedit_act 函式的特徵碼
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新 Linux 核心版本至 7.1-rc7 或以上，或者套用相關的修補程式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Copy-on-Write (COW)**: 一種記憶體管理技術，允許多個進程共享同一塊記憶體空間。當其中一個進程嘗試修改這塊記憶體空間時，系統會自動創建一個新的複製，然後修改新的複製。
* **tcf_pedit_act**: 一個 Linux 核心函式，負責封包標頭的編輯與重寫。
* **skb_ensure_writable**: 一個 Linux 核心函式，負責計算安全的寫入時複製範圍。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176912)
- [MITRE ATT&CK](https://attack.mitre.org/)


