---
layout: post
title:  "A Malicious SIM Card Can Run Attacker Code Inside the Modems Behind Cellular IoT Devices"
date:   2026-08-11 12:46:16 +0000
categories: [security]
severity: critical
---

# 🚨 SIM 卡遠程命令執行漏洞：解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: AT 命令、SIM 卡 Proactive Capability、Qualcomm 通信處理器

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Qualcomm 通信處理器中的 AT 命令處理機制存在漏洞，允許惡意 SIM 卡發送任意 AT 命令，從而實現遠程命令執行。
* **攻擊流程圖解**:
  1. 惡意 SIM 卡發送 AT 命令至 Qualcomm 通信處理器。
  2. 處理器執行 AT 命令，允許 SIM 卡訪問設備的檔案系統和其他資源。
  3. SIM 卡利用這些權限執行任意代碼，實現遠程命令執行。
* **受影響元件**: Qualcomm 基於的通訊處理器，包括 Quectel EC25、EG25 和 RM52xN 系列模組。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意 SIM 卡需要被插入設備的 SIM 卡槽中。
* **Payload 建構邏輯**:

    ```
    
    python
    import serial
    
    # 打開串口連接
    ser = serial.Serial('/dev/ttyUSB0', 115200)
    
    # 發送 AT 命令
    ser.write(b'AT+RUNAT="your_command"')
    
    # 關閉串口連接
    ser.close()
    
    ```
  *範例指令*: 使用 `curl` 發送 AT 命令至設備。

```

bash
curl -X POST 'http://example.com/at_command' -d 'AT+RUNAT="your_command"'

```
* **繞過技術**: 可以利用 WAF 和 EDR 的繞過技巧，例如使用編碼的 AT 命令或利用設備的其他漏洞。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /dev/ttyUSB0 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule AT_Command_Detection {
      meta:
        description = "Detect AT command execution"
        author = "Your Name"
      strings:
        $at_command = "AT+RUNAT"
      condition:
        $at_command in (0..100) of file
    }
    
    ```
  *或者是具體的 SIEM 查詢語法 (Splunk/Elastic)*:

```

sql
index=your_index (AT+RUNAT OR AT+COPS) | stats count as num_events by src_ip

```
* **緩解措施**: 更新 Qualcomm 通信處理器的固件，禁用 AT 命令處理機制，或者限制 SIM 卡的訪問權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AT 命令 (AT Command)**: 一種用於控制和配置電話和其他通訊設備的命令語言。
* **SIM 卡 Proactive Capability**: SIM 卡的一種功能，允許它主動發送命令至設備。
* **Qualcomm 通信處理器 (Qualcomm Communication Processor)**: 一種用於手機和其他通訊設備的處理器，負責處理通訊協議和命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/a-malicious-sim-card-can-run-attacker.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


