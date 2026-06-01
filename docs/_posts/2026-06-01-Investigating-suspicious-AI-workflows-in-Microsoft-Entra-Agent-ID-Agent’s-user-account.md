---
layout: post
title:  "Investigating suspicious AI workflows in Microsoft Entra Agent ID: Agent’s user account"
date:   2026-06-01 17:24:51 +0000
categories: [security]
severity: high
---

# 🔥 解析 Microsoft Entra ID 中的 Teams 懷疑活動：利用 Graph API 和 Agent User 進行攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Graph API, Agent User, OAuth, PowerShell

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Entra ID 中的 Agent User 可以利用 Graph API 發送 Teams 訊息，且沒有適當的驗證和授權機制。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個 Agent User 並將其與一個合法的 Teams 用戶連結。
    2. 攻擊者使用 Agent User 的憑證和 OAuth 權限發送 Teams 訊息。
    3. Teams 訊息包含惡意連結或代碼，導致用戶執行惡意動作。
* **受影響元件**: Microsoft Entra ID、Microsoft Teams、Graph API

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個 Agent User 並將其與一個合法的 Teams 用戶連結。
* **Payload 建構邏輯**:

    ```
    
    powershell
        $TargetEntraTenantID = 'INSERT_YOUR_TENANT_ID'
        $BlueprintSecret = 'INSERT_BLUEPRINT_SECRET'
        $BlueprintID = 'INSERT_BLUEPRINT_ID'
        $TargetAgentIdentityId = 'INSERT_AGENT_IDENTITY_ID'
        $TargetLinkedAgentUserAccount = 'INSERT_AGENT_USER_UPN'
        $TargetTeamName = 'Our Team'
        $TargetChannelName = 'Team Chat'
    
        # Follow the agent user flow documented here: https://learn.microsoft.com/en-us/entra/agent-id/agent-user-oauth-flow
        # 1. Request an exchange token using the blueprint client secret to authenticate
        $Result = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$TargetEntraTenantID/oauth2/v2.0/token" -Method Post -ContentType 'application/x-www-form-urlencoded' -Body @"
        client_id=$BlueprintID
        &client_secret=$BlueprintSecret
        &fmi_path=$TargetAgentIdentityId
        &grant_type=client_credentials
        &scope=api://AzureADTokenExchange/.default
        "@
        $Token = $Result.Content | ConvertFrom-Json
    
        # 2. Agent identity requests a token to impersonate its linked agent user.
        $Result = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$TargetEntraTenantID/oauth2/v2.0/token" -Method Post -ContentType 'application/x-www-form-urlencoded' -Body @"
        client_id=$TargetAgentIdentityId
        &scope=api://AzureADTokenExchange/.default
        &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
        &client_assertion=$($Token.access_token)
        &grant_type=client_credentials
        "@
        $BearerToken = $Result.Content | ConvertFrom-Json
    
        # Agent user obtains bearer token by sending an OBO token exchange request.
        $Result = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$TargetEntraTenantID/oauth2/v2.0/token" -Method Post -ContentType 'application/x-www-form-urlencoded' -Body @"
        client_id=$TargetAgentIdentityId
        &scope=https://graph.microsoft.com/.default
        &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
        &client_assertion=$($Token.access_token)
        &user_federated_identity_credential=$($BearerToken.access_token)
        &username=$TargetLinkedAgentUserAccount
        &grant_type=user_fic
        &requested_token_use=on_behalf_of
        "@
        $AgentUserBearerToken = $Result.Content | ConvertFrom-Json
        $AccessToken = ConvertTo-SecureString -String $AgentUserBearerToken.access_token -AsPlainText -Force
        Connect-MgGraph -AccessToken $AccessToken
    
        # Confirm the OAuth scope that your token is granted
        (Get-MgContext).Scopes
    
        $TargetTeam = Get-MgBetaTeam -Filter "displayName eq '$TargetTeamName'"
        $TeamChannel = Get-MgBetaTeamChannel -TeamId $TargetTeam.Id -Filter "displayName eq '$TargetChannelName'"
    
        # Send the suspicious message as the agent user
        New-MgBetaTeamChannelMessage -TeamId $TargetTeam.Id -ChannelId $TeamChannel.Id -Body @{contentType = 'html'; content = '<a href="https://domoarigato.ai/">Greetings from your robot overlords.</a>'}
        Disconnect-MgGraph
    
    ```
* **繞過技術**: 攻擊者可以使用不同的 OAuth 權限和憑證來繞過安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 51.3.97.221 | domoarigato.ai |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule suspicious_teams_message {
            meta:
                description = "Detects suspicious Teams messages"
                author = "Your Name"
            strings:
                $teams_message = "https://domoarigato.ai/"
            condition:
                $teams_message
        }
    
    ```
* **緩解措施**: 
    1. 刪除可疑的 Teams 訊息。
    2. 禁用可疑的 Agent User。
    3. 更新 Teams Messaging Policy 來允許刪除 Agent User 的訊息。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Graph API**: Microsoft Graph API 是一個 RESTful API，提供了存取 Microsoft 服務的功能，例如 Teams、OneDrive、Outlook 等。
* **Agent User**: Agent User 是一個特殊的使用者帳戶，代表了一個應用程式或服務，可以在 Microsoft 服務中執行動作。
* **OAuth**: OAuth 是一個授權框架，允許應用程式在不需要使用者密碼的情況下存取使用者的資源。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-teams/)
- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/)
- [OAuth](https://oauth.net/)


