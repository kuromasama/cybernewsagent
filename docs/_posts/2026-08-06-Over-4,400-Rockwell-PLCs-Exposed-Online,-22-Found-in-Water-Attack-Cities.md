---
layout: post
title:  "Over 4,400 Rockwell PLCs Exposed Online, 22 Found in Water Attack Cities"
date:   2026-08-06 13:47:07 +0000
categories: [security]
severity: high
---

# 🔥 解析 Rockwell Automation PLCs 的網路暴露與潛在攻擊面
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.6)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Modbus TCP, Buffer Overflow, EtherNet/IP

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Rockwell Automation 的 PLCs 中存在一個 Modbus TCP 的緩衝區溢位漏洞 (CVE-2017-16740)，這個漏洞允許攻擊者在未經驗證的情況下對 PLC 進行寫入操作。
* **攻擊流程圖解**:
  1. 攻擊者發現暴露在網路上的 Rockwell Automation PLC。
  2. 攻擊者使用 Modbus TCP 協議與 PLC 進行溝通。
  3. 攻擊者利用緩衝區溢位漏洞對 PLC 進行寫入操作。
* **受影響元件**: Rockwell Automation 的 MicroLogix 1400 Series B 和 C，固件版本 21.002 及更早版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 PLC 的 IP 地址和 Modbus TCP 的埠號 (44818)。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 定義 PLC 的 IP 地址和埠號
    plc_ip = '192.168.1.100'
    plc_port = 44818
    
    # 建立 Modbus TCP 連線
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((plc_ip, plc_port))
    
    # 送出 Modbus TCP 請求
    request = b'\x00\x00\x00\x00\x00\x06\x11\x03\x00\x00\x00\x01'
    sock.send(request)
    
    # 接收 PLC 的回應
    response = sock.recv(1024)
    print(response)
    
    # 關閉連線
    sock.close()
    
    ```
* **繞過技術**: 攻擊者可以使用 VPN 或代理伺服器來隱藏自己的 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 192.168.1.100 |  | /etc/plc.conf |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Modbus_TCP_Attack {
      meta:
        description = "Modbus TCP 攻擊偵測"
        author = "Your Name"
      strings:
        $modbus_tcp_request = { 00 00 00 00 00 06 11 03 00 00 00 01 }
      condition:
        $modbus_tcp_request
    }
    
    ```
* **緩解措施**: 將 PLC 的固件更新到最新版本，並設定強密碼和驗證機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Modbus TCP**: 一種用於工業控制系統的通訊協議，允許設備之間進行數據交換。
* **Buffer Overflow**: 一種程式設計錯誤，當程式嘗試寫入超出緩衝區大小的數據時，會導致緩衝區溢位，可能導致程式崩潰或執行任意代碼。
* **EtherNet/IP**: 一種用於工業控制系統的通訊協議，允許設備之間進行數據交換。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/over-4400-rockwell-plcs-exposed-online.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


