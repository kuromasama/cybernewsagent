---
layout: post
title:  "TCLBANKER Banking Trojan Targets Financial Platforms via WhatsApp and Outlook Worms"
date:   2026-05-08 19:07:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TCLBANKER 攻擊：巴西銀行木馬的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL side-loading, anti-analysis, WebSocket, social engineering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TCLBANKER 利用 DLL side-loading 技術，通過 Logitech 的 Logi AI Prompt Builder 程序來載入惡意 DLL ("screen_retriever_plugin.dll")，從而繞過分析工具和防毒軟件的檢測。
* **攻擊流程圖解**:
  1. User downloads malicious ZIP file
  2. ZIP file extracts malicious MSI installer
  3. MSI installer installs Logi AI Prompt Builder with malicious DLL
  4. Logi AI Prompt Builder loads malicious DLL
  5. Malicious DLL executes and deploys banking trojan and worm components
* **受影響元件**: Logitech Logi AI Prompt Builder, Windows 10/11, Microsoft Outlook, WhatsApp Web

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Victim must have Logitech Logi AI Prompt Builder installed, and must be using WhatsApp Web or Microsoft Outlook.
* **Payload 建構邏輯**:

    ```
    
    python
    # Example payload structure
    payload = {
        "type": "tclbanker",
        "version": "1.0",
        "config": {
            "target": "banking_app",
            "url": "https://example.com"
        }
    }
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST -H "Content-Type: application/json" -d '{"type": "tclbanker", "version": "1.0", "config": {"target": "banking_app", "url": "https://example.com"}}' https://example.com/api
    
    ```
* **繞過技術**: TCLBANKER 使用 anti-analysis 技術，包括環境檢查、語言檢查和系統盤檢查，來避免被分析工具和防毒軟件檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\screen_retriever_plugin.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule tclbanker {
        meta:
            description = "TCLBANKER banking trojan"
            author = "Your Name"
        strings:
            $a = "screen_retriever_plugin.dll"
            $b = "Logi AI Prompt Builder"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 升級 Logitech Logi AI Prompt Builder 至最新版本，禁用 WhatsApp Web 和 Microsoft Outlook 的自動登入功能，啟用 Windows Defender 和防毒軟件的實時保護功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL side-loading**: 想像兩個 DLL 文件同時被載入記憶體，且其中一個 DLL 文件是惡意的。技術上是指惡意 DLL 文件被載入記憶體，從而繞過分析工具和防毒軟件的檢測。
* **anti-analysis**: 想像一個程序試圖避免被分析工具和防毒軟件檢測。技術上是指惡意程序使用各種技術，例如環境檢查、語言檢查和系統盤檢查，來避免被分析工具和防毒軟件檢測。
* **WebSocket**: 想像兩個程序之間的實時通信。技術上是指 WebSocket 是一個允許兩個程序之間進行實時通信的協議。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/tclbanker-banking-trojan-targets.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


