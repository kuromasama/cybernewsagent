---
layout: post
title:  "ServiceNow AI平臺爆漏洞，允許攻擊者冒用帳號並劫持AI代理流程"
date:   2026-01-21 06:27:49 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ServiceNow BodySnatcher 漏洞：虛擬代理 API 的安全風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.3)
> * **受駭指標**: 身分驗證繞過和任意使用者身分冒用
> * **關鍵技術**: 靜態憑證、自動連結邏輯、虛擬代理 API

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: BodySnatcher 漏洞的成因在於 ServiceNow 的 Virtual Agent API 和 Now Assist AI Agents 的外部整合模式中使用了靜態憑證和自動連結邏輯。這使得攻擊者可以使用共用的靜態憑證和電子郵件位址來冒用任意使用者的身分。
* **攻擊流程圖解**:
  1. 攻擊者取得共用的靜態憑證。
  2. 攻擊者使用靜態憑證和電子郵件位址來連結到 ServiceNow 帳號。
  3. 攻擊者使用被冒用帳號的權限來執行平臺內的操作。
* **受影響元件**: Now Assist AI Agents 的 5.0.24 至 5.1.17 版本和 5.2.0 至 5.2.18 版本，虛擬代理外部介面 sn_va_as_service 的 3.15.1 以下版本和 4.0.0 至 4.0.3 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得共用的靜態憑證和電子郵件位址。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 共用的靜態憑證
    certificate = "path/to/certificate"
    
    # 電子郵件位址
    email = "target@example.com"
    
    # 連結到 ServiceNow 帳號
    response = requests.post(
        "https://example.service-now.com/api/v1/agents",
        headers={"Authorization": f"Bearer {certificate}"},
        json={"email": email}
    )
    
    # 使用被冒用帳號的權限來執行平臺內的操作
    if response.status_code == 200:
        # 執行操作
        pass
    
    ```
* **繞過技術**: 攻擊者可以使用靜態憑證和電子郵件位址來繞過 MFA 和 SSO 等既有控管。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.service-now.com | /api/v1/agents |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule BodySnatcher {
      meta:
        description = "Detects BodySnatcher attacks"
      strings:
        $certificate = "path/to/certificate"
      condition:
        $certificate in (pe.files[0].data)
    }
    
    ```
* **緩解措施**: 更新 Now Assist AI Agents 和虛擬代理外部介面到最新版本，使用動態憑證和強化的身份驗證機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **靜態憑證 (Static Certificate)**: 一種不會變化的憑證，通常用於自動連結和身份驗證。
* **自動連結邏輯 (Auto-Linking Logic)**: 一種機制，自動連結使用者的電子郵件位址和 ServiceNow 帳號。
* **虛擬代理 API (Virtual Agent API)**: 一種 API，允許外部應用程式和 ServiceNow 互動。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173500)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


