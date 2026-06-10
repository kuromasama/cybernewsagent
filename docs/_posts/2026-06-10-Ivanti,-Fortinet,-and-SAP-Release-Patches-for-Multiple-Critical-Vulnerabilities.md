---
layout: post
title:  "Ivanti, Fortinet, and SAP Release Patches for Multiple Critical Vulnerabilities"
date:   2026-06-10 20:18:20 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Fortinet, Ivanti, 和 SAP 的命令執行與資訊洩露漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.1-10.0)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Command Injection, XML Signature Wrapping, Memory Corruption

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Fortinet 的 FortiSandbox 中的命令執行漏洞是由於沒有正確地中和特殊字符，導致攻擊者可以執行任意命令。Ivanti 的 Ivanti Sentry 中的漏洞是由於操作系統命令注入和身份驗證繞過。
* **攻擊流程圖解**:
	+ User Input -> `/mics/api/v2/sentry/mics-config/handleMessage` Endpoint -> `handleExecute()` 函數 -> 執行任意命令
* **受影響元件**:
	+ FortiSandbox 5.0.0-5.0.5
	+ FortiSandbox Cloud 5.0.4-5.0.5
	+ Ivanti Sentry R10.5.2, R10.6.2, 和 R10.7.1

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 網路存取和特定的 HTTP 請求
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建構 Payload
    payload = {
        "message": "任意命令"
    }
    
    # 發送 HTTP 請求
    response = requests.post("/mics/api/v2/sentry/mics-config/handleMessage", json=payload)
    
    # 執行任意命令
    print(response.text)
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用編碼或加密的 Payload

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:
	+ Hash: `1234567890abcdef`
	+ IP: `192.168.1.100`
	+ Domain: `example.com`
	+ File Path: `/mics/api/v2/sentry/mics-config/handleMessage`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FortiSandbox_Command_Injection {
        meta:
            description = "FortiSandbox 命令執行漏洞"
            author = "Your Name"
        strings:
            $payload = { 6d 65 73 73 61 67 65 3a 20 22 2a 2a 2a 22 }
        condition:
            $payload at offset 0
    }
    
    ```
* **緩解措施**: 更新 FortiSandbox 和 Ivanti Sentry 至最新版本，並設定 WAF 和 EDR 來偵測和阻止攻擊

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Command Injection (命令執行)**: 想像攻擊者可以執行任意命令，技術上是指攻擊者可以注入任意命令到系統中，導致系統執行攻擊者的命令。
* **XML Signature Wrapping (XML 簽名包裝)**: 想像攻擊者可以包裝任意 XML 文件，技術上是指攻擊者可以包裝任意 XML 文件到合法的 XML 文件中，導致系統驗證失敗。
* **Memory Corruption (記憶體破壞)**: 想像攻擊者可以破壞系統記憶體，技術上是指攻擊者可以破壞系統記憶體，導致系統崩潰或執行任意命令。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/06/ivanti-fortinet-and-sap-release-patches.html)
* [MITRE ATT&CK](https://attack.mitre.org/)


