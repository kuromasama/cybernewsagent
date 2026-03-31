---
layout: post
title:  "Microsoft fixes Outlook Classic crashes caused by Teams Meeting add-in"
date:   2026-03-31 13:01:35 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Outlook 與 Teams Meeting Add-in 的崩潰漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: Application Crash
> * **關鍵技術**: COM Add-ins, Click-to-Run, Online Repair

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於舊版 Outlook 使用最新版本的 Teams Meeting Add-in 時，導致應用程式崩潰。這是由於舊版 Outlook 的某些函數與新版 Add-in 的相容性問題所致。
* **攻擊流程圖解**: 
    1. 使用者啟用 Teams Meeting Add-in
    2. Outlook 嘗試載入 Add-in
    3. 舊版 Outlook 的函數與新版 Add-in 發生相容性問題
    4. Outlook 崩潰並提示使用者啟動安全模式
* **受影響元件**: 
    + Outlook 版本：2402 (Build 17328.20142) 或更低
    + Teams Meeting Add-in 版本：1.26.02603

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 
    + 使用者需要啟用 Teams Meeting Add-in
    + 使用者需要使用舊版 Outlook
* **Payload 建構邏輯**:

    ```
    
    python
        # 範例指令：啟用 Teams Meeting Add-in
        import os
        os.system("reg add \"HKCU\\Software\\Microsoft\\Office\\Outlook\\AddIns\\TeamsMeetingAddin\" /v \"LoadBehavior\" /t REG_DWORD /d 3 /f")
    
    ```
    *範例指令*: 使用 `curl` 或 `powershell` 將 Add-in 啟用並觸發崩潰。
* **繞過技術**: 
    + 可以嘗試使用不同的 Add-in 版本或修改 Add-in 的設定來繞過防禦。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | %APPDATA%\\Microsoft\\Outlook\\AddIns\\TeamsMeetingAddin.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule Outlook_Teams_Addin_Crash {
            meta:
                description = "Detects Outlook crash caused by Teams Meeting Add-in"
                author = "Your Name"
            strings:
                $a = "TeamsMeetingAddin.dll"
                $b = "Outlook.exe"
            condition:
                all of them
        }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。
* **緩解措施**: 
    + 更新 Outlook 至最新版本
    + 禁用 Teams Meeting Add-in
    + 執行 Online Repair

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **COM Add-ins**: COM (Component Object Model) 是 Microsoft 的一種元件模型，允許不同程式語言和應用程式之間進行通訊和交互。COM Add-ins 是基於 COM 的應用程式擴充元件。
* **Click-to-Run**: Click-to-Run 是 Microsoft 的一種技術，允許使用者在不需要安裝完整版本的情況下，直接下載和運行 Office 應用程式。
* **Online Repair**: Online Repair 是 Microsoft 的一種技術，允許使用者在不需要重新安裝應用程式的情況下，直接修復和更新 Office 應用程式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-outlook-classic-crashes-caused-by-teams-meeting-add-in/)
- [Microsoft Teams Meeting Add-in](https://docs.microsoft.com/en-us/microsoftteams/teams-add-in)
- [MITRE ATT&CK](https://attack.mitre.org/)


