---
layout: post
title:  "18-Year-Old Linux SCTP Flaw Could Let Local Users Gain Root and Escape Containers"
date:   2026-08-07 12:44:59 +0000
categories: [security]
severity: high
---

# 🔥 解析 Linux SCTP 網路代碼中的 use-after-free 漏洞：SCTPhantom

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS v4.0: 8.5)
> * **受駭指標**: Local Privilege Escalation (LPE)
> * **關鍵技術**: use-after-free, SCTP, Dynamic Address Reconfiguration

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SCTPhantom 漏洞源於 Linux 的 SCTP 網路代碼中，當處理刪除請求時，內核會檢查封包的源地址，但實際上卻對不同的地址進行操作，導致釋放後重用的情況。
* **攻擊流程圖解**:
  1. 攻擊者發送一個包含刪除請求的封包。
  2. 內核檢查封包的源地址並進行刪除操作。
  3. 但是，內核實際上對不同的地址進行操作，導致釋放後重用的情況。
* **受影響元件**: Linux 2.6.25 以後的所有版本，包括 7.1.6、6.18.42、6.12.101 和 6.6.148。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有本地權限，並且需要 SCTP 網路代碼可達。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 建立 SCTP 連接
    sctp_socket = socket.socket(socket.AF_INET, socket.SOCK_SCTP)
    
    # 發送刪除請求
    delete_request = b'\x01\x00\x00\x00\x00\x00\x00\x00'
    sctp_socket.send(delete_request)
    
    # 利用 use-after-free 漏洞
    exploit_payload = b'\x02\x00\x00\x00\x00\x00\x00\x00'
    sctp_socket.send(exploit_payload)
    
    ```
* **繞過技術**: 攻擊者可以通過啟用 `net.sctp.addip_enable` 和 `net.sctp.addip_noauth_enable` sysctls 來繞過某些限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SCTPhantom_Detection {
      meta:
        description = "SCTPhantom use-after-free 漏洞偵測"
      strings:
        $sctp_delete_request = { 01 00 00 00 00 00 00 00 }
      condition:
        $sctp_delete_request
    }
    
    ```
* **緩解措施**: 更新 Linux 內核版本至 7.1.6、6.18.42、6.12.101 或 6.6.148 以上版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SCTP (Stream Control Transmission Protocol)**: 一種允許單一連接在多個網路路徑上運行的傳輸協議。
* **use-after-free**: 一種記憶體相關的漏洞，當程式釋放記憶體後，仍然嘗試存取該記憶體區塊。
* **Dynamic Address Reconfiguration**: 一種允許在連接中添加或刪除地址的功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/18-year-old-linux-sctp-flaw-could-let.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


