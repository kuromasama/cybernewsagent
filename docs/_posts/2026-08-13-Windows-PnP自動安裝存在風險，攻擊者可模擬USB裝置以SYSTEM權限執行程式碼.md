---
layout: post
title:  "Windows PnP自動安裝存在風險，攻擊者可模擬USB裝置以SYSTEM權限執行程式碼"
date:   2026-08-13 12:53:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Plug and Pwn：Windows 隨插即用漏洞利用技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: LPE (Local Privilege Escalation) 和 RCE (Remote Code Execution)
> * **關鍵技術**: USB 裝置偽造、Windows 隨插即用 (Plug and Play)、驅動程式漏洞利用

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Windows 隨插即用機制中的驅動程式安裝流程存在漏洞，允許攻擊者偽造 USB 裝置並安裝有問題的驅動程式。
* **攻擊流程圖解**:
  1. 攻擊者偽造 USB 裝置並連接到目標系統。
  2. Windows 系統偵測到新裝置並嘗試安裝驅動程式。
  3. 攻擊者利用驅動程式漏洞獲得 SYSTEM 權限。
  4. 攻擊者利用 SYSTEM 權限執行任意程式碼。
* **受影響元件**: Windows 11、Sierra Wireless 驅動程式、Sony FeliCa 驅動程式

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要物理存取目標系統或遠端桌面環境。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    import usb.core
    import usb.util
    
    #偽造 USB 裝置
    dev = usb.core.Device(0x03EB, 0x6124)  # Sierra Wireless 裝置 ID
    
    # 安裝驅動程式
    # ...
    
    # 利用驅動程式漏洞獲得 SYSTEM 權限
    # ...
    
    ```
* **繞過技術**: 攻擊者可以利用 USB 裝置重新導向功能繞過遠端桌面環境的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | example.com |
| File Path | C:\Windows\System32\drivers\sierra_wireless.sys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Sierra_Wireless_Driver {
      meta:
        description = "Sierra Wireless 驅動程式漏洞利用"
        author = "Your Name"
      strings:
        $a = { 12 34 56 78 90 ab cd ef }
      condition:
        $a at 0
    }
    
    ```
* **緩解措施**: 更新 Windows 系統和驅動程式至最新版本，禁用遠端桌面環境的 USB 裝置重新導向功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Plug and Play (PnP)**: 一種允許系統自動偵測和安裝硬體裝置的技術。
* **驅動程式 (Driver)**: 一種軟體元件，負責管理硬體裝置的溝通和控制。
* **SYSTEM 權限 (SYSTEM Privilege)**: Windows 系統中最高的權限級別，允許使用者執行任意程式碼。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.ithome.com.tw/news/178117)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


