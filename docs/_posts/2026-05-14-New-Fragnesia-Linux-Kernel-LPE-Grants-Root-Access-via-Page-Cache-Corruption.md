---
layout: post
title:  "New Fragnesia Linux Kernel LPE Grants Root Access via Page Cache Corruption"
date:   2026-05-14 08:29:55 +0000
categories: [security]
severity: high
---

# 🔥 解析 Fragnesia：Linux 核心的 XFRM ESP-in-TCP 子系統漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數: 7.8)
> * **受駭指標**: Local Privilege Escalation (LPE)
> * **關鍵技術**: XFRM ESP-in-TCP, Kernel Page Cache, Deterministic Page-Cache Corruption Primitive

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Fragnesia 漏洞源於 Linux 核心的 XFRM ESP-in-TCP 子系統中的一個邏輯錯誤。這個錯誤允許未經授權的本地攻擊者修改內核頁面緩存中的唯讀文件內容，並通過確定的頁面緩存腐壞原語獲得根權限。
* **攻擊流程圖解**:
  1. 攻擊者創建一個特定的 TCP 連接，利用 XFRM ESP-in-TCP 子系統的漏洞。
  2. 攻擊者修改內核頁面緩存中的唯讀文件內容，例如 `/usr/bin/su` 二進制文件。
  3. 攻擊者利用修改後的頁面緩存內容，獲得根權限。
* **受影響元件**: Linux 核心版本 5.10 至 5.19，包括多個主要 Linux 發行版。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 未經授權的本地權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 創建一個 TCP 連接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 8080))
    
    # 修改內核頁面緩存中的唯讀文件內容
    # ...
    
    ```
  *範例指令*: 使用 `curl` 工具發送一個特定的 HTTP 請求，利用 XFRM ESP-in-TCP 子系統的漏洞。
* **繞過技術**: AppArmor 限制可能需要額外的繞過技術。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Fragnesia {
      meta:
        description = "Fragnesia Linux 核心漏洞"
      strings:
        $a = "XFRM ESP-in-TCP"
      condition:
        $a
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。
* **緩解措施**: 除了更新修補之外，還可以考慮以下措施：
  + 禁用 XFRM ESP-in-TCP 子系統。
  + 限制未經授權的本地權限。
  + 監控內核頁面緩存中的唯讀文件內容。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **XFRM ESP-in-TCP**: XFRM (eXtended Flow Management) 是 Linux 核心的一個子系統，提供了對 IPsec (Internet Protocol Security) 的支持。ESP-in-TCP 是 XFRM 中的一個特性，允許在 TCP 連接中使用 ESP (Encapsulating Security Payload) 封包。
* **Kernel Page Cache**: 內核頁面緩存是一個緩存機制，允許內核快速存取文件系統中的文件內容。
* **Deterministic Page-Cache Corruption Primitive**: 一個確定的頁面緩存腐壞原語，是指攻擊者可以通過修改內核頁面緩存中的唯讀文件內容，獲得根權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/new-fragnesia-linux-kernel-lpe-grants.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


