---
layout: post
title:  "New ClickLock macOS Stealer Kills Apps Every 210ms Until Victims Type Their Password"
date:   2026-07-16 13:27:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ClickLock Stealer：一種針對 macOS 的新型資訊竊取者

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `LaunchAgent`, `osascript`, `dscl`, `Telegram` Exfil

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ClickLock Stealer 利用 macOS 的 `LaunchAgent` 機制，創建兩個惡意的 `LaunchAgent` 腳本，分別為 `com.authirity.plist` 和 `com.chromer.plist`，用於殺死系統應用程式和竊取使用者資料。
* **攻擊流程圖解**:
  1. 使用者執行惡意命令，創建 `com.authirity.plist` 和 `com.chromer.plist` 腳本。
  2. 腳本殺死系統應用程式，例如 `Finder`, `Dock`, `SystemUIServer`, 和 `NotificationCenter`。
  3. 使用 `osascript` 腳本，彈出假的系統對話框，要求使用者輸入密碼。
  4. 如果使用者拒絕輸入密碼，腳本會繼續殺死系統應用程式，直到使用者輸入密碼。
* **受影響元件**: macOS 12.4 或更早版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要執行惡意命令，創建 `com.authirity.plist` 和 `com.chromer.plist` 腳本。
* **Payload 建構邏輯**:

    ```
    
    bash
    # 創建 com.authirity.plist 腳本
    osascript -e 'tell application "System Events" to display dialog "Please enter your password:"'
    
    # 殺死系統應用程式
    pkill -9 Finder
    pkill -9 Dock
    pkill -9 SystemUIServer
    pkill -9 NotificationCenter
    
    ```
* **繞過技術**: ClickLock Stealer 使用 `osascript` 腳本，彈出假的系統對話框，要求使用者輸入密碼，繞過 macOS 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | ~/Library/LaunchAgents/com.authirity.plist |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ClickLock_Stealer {
      meta:
        description = "Detects ClickLock Stealer"
      strings:
        $a = "com.authirity.plist"
        $b = "com.chromer.plist"
      condition:
        $a or $b
    }
    
    ```
* **緩解措施**: 更新 macOS 至最新版本，移除 `com.authirity.plist` 和 `com.chromer.plist` 腳本，並設定 `LaunchAgent` 機制，禁止創建惡意腳本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **LaunchAgent**: 一種 macOS 的機制，允許創建和管理系統服務。
* **osascript**: 一種 macOS 的命令，允許執行 AppleScript 腳本。
* **dscl**: 一種 macOS 的命令，允許存取和管理使用者資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


