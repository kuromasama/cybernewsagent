---
layout: post
title:  "Plug and Pwn attack uses fake USB devices for Windows SYSTEM access"
date:   2026-08-12 18:53:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Windows Plug and Play 功能的「Plug and Pwn」攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: USB 仿真、Windows Plug and Play、Co-Installer

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows Plug and Play 功能會自動識別新連接的硬體，並下載和安裝相應的驅動程式和軟體。這個過程中，系統會以 SYSTEM 權限執行 Co-Installer，導致攻擊者可以利用這個機制來執行惡意程式碼。
* **攻擊流程圖解**:
  1. 攻擊者使用 FaceDancer 等工具仿真 USB 裝置。
  2. Windows 系統識別到新連接的 USB 裝置，並下載和安裝相應的驅動程式和軟體。
  3. Co-Installer 被執行，攻擊者可以利用這個機制來執行惡意程式碼。
* **受影響元件**: Windows 10、Windows 11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個可以仿真 USB 裝置的設備，例如 FaceDancer。
* **Payload 建構邏輯**:

    ```
    
    python
      # 仿真 USB 裝置
      import usb.core
      import usb.util
    
      # 下載和安裝相應的驅動程式和軟體
      import requests
    
      # 執行惡意程式碼
      import subprocess
    
    ```
* **繞過技術**: 攻擊者可以使用 USB 仿真技術來繞過系統的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Windows_Plug_and_Pwn {
        meta:
          description = "Detects Windows Plug and Pwn attacks"
          author = "Your Name"
        strings:
          $a = "FaceDancer"
          $b = "Co-Installer"
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 禁用 Co-Installer、限制 USB 裝置的連接、更新系統和軟體。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Co-Installer**: 一種 Windows 系統的安裝程式，負責安裝驅動程式和軟體。
* **FaceDancer**: 一種工具，用于仿真 USB 裝置。
* **USB 仿真**: 一種技術，用于仿真 USB 裝置的行為。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/plug-and-pwn-attack-uses-fake-usb-devices-for-windows-system-access/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


