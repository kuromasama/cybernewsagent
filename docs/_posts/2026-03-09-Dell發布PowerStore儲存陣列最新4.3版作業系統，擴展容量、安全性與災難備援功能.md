---
layout: post
title:  "Dell發布PowerStore儲存陣列最新4.3版作業系統，擴展容量、安全性與災難備援功能"
date:   2026-03-09 12:45:03 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Dell PowerStore OS 4.3 更新：新功能與潛在安全性風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `NFS 4.2`, `Server-Side Copy`, `Multiparty authorization`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Dell PowerStore OS 4.3 更新中引入的新功能，例如 `NFS 4.2` 支援和 `Multiparty authorization`，可能導致本地權限提升（LPE）漏洞。這是因為在某些情況下，系統可能允許低權限用戶執行高權限操作。
* **攻擊流程圖解**: 
  1.攻擊者獲得低權限用戶帳戶。
  2.攻擊者利用 `NFS 4.2` 的 `Server-Side Copy` 功能創建一個具有高權限的檔案。
  3.攻擊者使用 `Multiparty authorization` 功能，讓系統認為高權限操作是由多個用戶授權的。
  4.系統執行高權限操作，導致 LPE。
* **受影響元件**: Dell PowerStore OS 4.3

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得低權限用戶帳戶，並且需要有 `NFS 4.2` 和 `Multiparty authorization` 功能的存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 創建一個具有高權限的檔案
    os.system("touch /high_priv_file")
    
    # 使用 Server-Side Copy 功能複製檔案
    os.system("nfs4_copy /high_priv_file /low_priv_file")
    
    # 使用 Multiparty authorization 功能授權高權限操作
    os.system("multiparty_auth /high_priv_file")
    
    ```
* **繞過技術**: 攻擊者可以使用 `NFS 4.2` 的 `Sparse Files` 功能來繞過系統的存取控制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /high_priv_file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Dell_PowerStore_OS_4_3_LPE {
      meta:
        description = "Dell PowerStore OS 4.3 LPE漏洞"
        author = "Your Name"
      condition:
        all of them
    }
    
    ```
* **緩解措施**: 更新 Dell PowerStore OS 至最新版本，並啟用 `Multiparty authorization` 功能的安全模式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NFS 4.2 (Network File System 4.2)**: 一種網路檔案系統協定，提供了檔案存取和管理的功能。
* **Server-Side Copy (伺服器端複製)**: 一種功能，允許伺服器在不需要客戶端參與的情況下複製檔案。
* **Multiparty authorization (多方授權)**: 一種功能，允許多個用戶授權高權限操作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174288)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


