---
layout: post
title:  "New Cisco DoS flaw requires manual reboot to revive devices"
date:   2026-05-06 19:28:25 +0000
categories: [security]
severity: high
---

# 🔥 解析 Cisco Crosswork Network Controller 和 Network Services Orchestrator 的 DoS 漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.6)
> * **受駭指標**: Denial of Service (DoS)
> * **關鍵技術**: 來源端口號碼未經適當限制、無驗證的遠端攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Cisco Crosswork Network Controller (CNC) 和 Network Services Orchestrator (NSO) 的來源端口號碼未經適當限制，導致攻擊者可以透過遠端、無驗證的方式對系統進行 DoS 攻擊。
* **攻擊流程圖解**:
  1. 攻擊者發送大量請求至目標系統。
  2. 系統未能限制來源端口號碼，導致系統資源耗盡。
  3. 系統變得無響應，導致合法使用者和依賴服務無法存取。
* **受影響元件**: Cisco CNC 7.1 和之前版本，Cisco NSO 6.3 和之前版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要能夠向目標系統發送請求。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 定義目標系統的 IP 和 Port
    target_ip = "192.168.1.100"
    target_port = 80
    
    # 建立 socket 連線
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 發送大量請求至目標系統
    for i in range(10000):
        sock.connect((target_ip, target_port))
        sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        sock.close()
    
    ```
* **繞過技術**: 攻擊者可以使用代理伺服器或 VPN 來隱藏自己的 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 192.168.1.100 | example.com | /var/log/apache2/access.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Cisco_CNC_DoS {
      meta:
        description = "Detects Cisco CNC DoS attacks"
        author = "Your Name"
      strings:
        $http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
      condition:
        $http_request at entry(0)
    }
    
    ```
* **緩解措施**: 更新 Cisco CNC 和 NSO 至最新版本，限制來源端口號碼，實施防火牆規則以阻止攻擊流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Denial of Service (DoS)**: 一種攻擊方式，旨在使目標系統無法提供服務。
* **來源端口號碼 (Source Port Number)**: 用於識別發送請求的端口號碼。
* **無驗證的遠端攻擊 (Unauthenticated Remote Attack)**: 一種攻擊方式，無需驗證即可對目標系統進行攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-cisco-dos-flaw-requires-manual-reboot-to-revive-devices/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1499/)


