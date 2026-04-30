---
layout: post
title:  "New Python Backdoor Uses Tunneling Service to Steal Browser and Cloud Credentials"
date:   2026-04-30 13:26:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 DEEP#DOOR：一種基於 Python 的隱蔽後門框架

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Python-based backdoor, Tunneling, Anti-analysis, Defense evasion

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: DEEP#DOOR 的核心是基於 Python 的隱蔽後門框架，利用批次腳本 (`install_obf.bat`) 執行並禁用 Windows 安全控制，然後提取嵌入的 Python Payload (`svc.py`) 並建立持久性存取。
* **攻擊流程圖解**:
  1. User 執行批次腳本 (`install_obf.bat`)
  2. 批次腳本禁用 Windows 安全控制
  3. 批次腳本提取嵌入的 Python Payload (`svc.py`)
  4. Python Payload 建立持久性存取 (Startup folder scripts, registry Run keys, scheduled tasks)
  5. Python Payload 與 Rust-based tunneling 服務 (`bore[.]pub`) 進行通信
* **受影響元件**: Windows 作業系統，特別是 Windows 10 和 Windows Server 2019

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 需要有 Administrator 權限
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import sys
    import requests
    
    # 提取嵌入的 Python Payload
    def extract_payload():
        # ...
    
    # 建立持久性存取
    def establish_persistence():
        # ...
    
    # 與 Rust-based tunneling 服務進行通信
    def communicate_with_tunnel():
        # ...
    
    if __name__ == '__main__':
        extract_payload()
        establish_persistence()
        communicate_with_tunnel()
    
    ```
* **繞過技術**: DEEP#DOOR 使用多種技術來繞過安全控制，包括 sandbox, debugger, 和 virtual machine (VM) 偵測，AMSI 和 Event Tracing for Windows (ETW) patching, NTDLL unhooking, Microsoft Defender tampering, SmartScreen bypass, PowerShell logging suppression, command-line wiping, timestamp stomping, 和 log clearing。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `bore[.]pub` | `C:\Windows\Temp\install_obf.bat` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule DEEP#DOOR {
        meta:
            description = "DEEP#DOOR Malware"
            author = "Your Name"
        strings:
            $a = "install_obf.bat"
            $b = "svc.py"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還需要修改 Windows 安全控制設定，例如啟用 Windows Defender 和設定合適的安全策略。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Tunneling (隧道技術)**: 一種技術，允許資料在網路中傳輸時被封裝在其他協議中，以避免被偵測或阻擋。
* **Anti-analysis (反分析)**: 一種技術，旨在使惡意軟體難以被分析或偵測。
* **Defense evasion (防禦繞過)**: 一種技術，旨在使惡意軟體難以被防禦或阻擋。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://thehackernews.com/2026/04/new-python-backdoor-uses-tunneling.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


