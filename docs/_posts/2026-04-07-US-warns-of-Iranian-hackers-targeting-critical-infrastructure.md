---
layout: post
title:  "US warns of Iranian hackers targeting critical infrastructure"
date:   2026-04-07 18:55:21 +0000
categories: [security]
severity: critical
---

# 🚨 解析伊朗駭客對美國基礎設施的網路攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: PLC (Programmable Logic Controller), HMI (Human-Machine Interface), SCADA (Supervisory Control and Data Acquisition)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 伊朗駭客利用 Rockwell/Allen-Bradley PLC 的漏洞，進行遠程代碼執行，從而控制美國基礎設施的網路。
* **攻擊流程圖解**:
  1.駭客發現網路暴露的PLC設備。
  2.駭客利用PLC的漏洞，進行遠程代碼執行。
  3.駭客控制PLC設備，操控HMI和SCADA系統。
* **受影響元件**: Rockwell/Allen-Bradley PLC設備，尤其是那些暴露在網路上的設備。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客需要知道PLC設備的IP地址和端口號。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 定義PLC設備的IP地址和端口號
    plc_ip = "192.168.1.100"
    plc_port = 102
    
    # 建立socket連接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((plc_ip, plc_port))
    
    # 發送payload
    payload = b"\x01\x02\x03\x04"
    sock.send(payload)
    
    # 接收回應
    response = sock.recv(1024)
    print(response)
    
    ```
* **繞過技術**: 駭客可以利用WAF和EDR的漏洞，繞過安全防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /plc/device |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule plc_exploit {
      meta:
        description = "PLC Exploit Detection"
        author = "Blue Team"
      strings:
        $a = { 01 02 03 04 }
      condition:
        $a at 0
    }
    
    ```
* **緩解措施**: 將PLC設備從網路中斷開，或者使用防火牆和入侵檢測系統進行保護。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PLC (Programmable Logic Controller)**: 一種可編程的邏輯控制器，用于控制和監控工業設備。
* **HMI (Human-Machine Interface)**: 人機界面，用于人類和機器之間的交互。
* **SCADA (Supervisory Control and Data Acquisition)**: 監控和數據采集系統，用于監控和控制工業設備。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/us-warns-of-iranian-hackers-targeting-critical-infrastructure/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


