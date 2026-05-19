---
layout: post
title:  "Microsoft Self-Service Password Reset abused in Azure data theft attacks"
date:   2026-05-19 19:45:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Storm-2949 攻擊：Microsoft 365 和 Azure 生產環境資料外洩
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 資料外洩 (Data Exfiltration)
> * **關鍵技術**: 社交工程 (Social Engineering), Microsoft Graph API, Azure RBAC

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Storm-2949 攻擊者利用社交工程手法，針對具有特權角色的使用者（如 IT 人員或高層領導）進行攻擊，獲得其 Microsoft Entra ID 認證，以便存取 Microsoft 365 應用程式中的資料。
* **攻擊流程圖解**:
  1. 攻擊者使用社交工程手法，假冒 IT 支援人員，要求目標使用者進行密碼重置。
  2. 攻擊者利用 Self-Service Password Reset (SSPR) 流程，重置目標使用者的密碼。
  3. 攻擊者移除多因素驗證 (MFA) 控制，然後在自己的設備上註冊 Microsoft Authenticator。
  4. 攻擊者使用 Microsoft Graph API 和自訂 Python 腳本，枚舉使用者、角色、應用程式和服務主體，評估每個案例的長期持續機會。
* **受影響元件**: Microsoft 365、Azure 生產環境

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要具有特權角色的使用者認證。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 使用 Microsoft Graph API 枚舉使用者和角色
    url = "https://graph.microsoft.com/v1.0/users"
    headers = {
        "Authorization": "Bearer <access_token>",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    
    # 使用自訂 Python 腳本下載 OneDrive 和 SharePoint 中的檔案
    import onedrive
    import sharepoint
    
    # ...
    
    ```
* **繞過技術**: 攻擊者可以使用社交工程手法，假冒 IT 支援人員，要求目標使用者進行密碼重置，繞過多因素驗證 (MFA) 控制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| <hash> | <ip> | <domain> | <file_path> |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Storm_2949 {
      meta:
        description = "Storm-2949 攻擊偵測"
        author = "Your Name"
      strings:
        $microsoft_graph_api = "https://graph.microsoft.com/v1.0/"
        $onedrive = "https://onedrive.com/"
      condition:
        $microsoft_graph_api and $onedrive
    }
    
    ```
* **緩解措施**: 啟用多因素驗證 (MFA) 控制，限制 Azure RBAC 權限，監控 Microsoft Graph API 和 OneDrive 的異常活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Microsoft Graph API**: Microsoft Graph API 是一個 RESTful API，提供存取 Microsoft 365 和 Azure 中的資料和服務。
* **Azure RBAC**: Azure RBAC (Role-Based Access Control) 是 Azure 中的角色基礎存取控制系統，提供細粒度的存取控制。
* **Self-Service Password Reset (SSPR)**: SSPR 是 Microsoft 365 中的一個功能，允許使用者自行重置密碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/microsoft-self-service-password-reset-abused-in-azure-data-theft-attacks/)
- [Microsoft Graph API 文件](https://docs.microsoft.com/en-us/graph/)
- [Azure RBAC 文件](https://docs.microsoft.com/en-us/azure/role-based-access-control/)


