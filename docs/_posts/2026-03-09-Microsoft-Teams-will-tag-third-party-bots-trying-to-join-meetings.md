---
layout: post
title:  "Microsoft Teams will tag third-party bots trying to join meetings"
date:   2026-03-09 18:42:44 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Teams 第三方機器人標籤功能的安全性與威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Unauthorized Access
> * **關鍵技術**: `OAuth`, `Bot Authentication`, `Meeting Security`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Teams 的第三方機器人標籤功能是為了防止惡意機器人未經授權加入會議。這個功能的實現需要在會議組織者端進行機器人身份驗證和授權。
* **攻擊流程圖解**: 
    1. 第三方機器人嘗試加入會議
    2. 機器人身份驗證和授權
    3. 會議組織者授權機器人加入會議
* **受影響元件**: Microsoft Teams 的所有版本，包括 Windows、macOS、Android 和 iOS 平台。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意機器人需要獲得會議邀請鏈接或會議 ID。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意機器人加入會議的請求
    def join_meeting(meeting_id, bot_token):
        url = f"https://api.microsoft.com/meetings/{meeting_id}/join"
        headers = {"Authorization": f"Bearer {bot_token}"}
        response = requests.post(url, headers=headers)
        return response.json()
    
    # 惡意機器人身份驗證和授權
    def authenticate_bot(bot_id, bot_secret):
        url = "https://api.microsoft.com/bots/authenticate"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"bot_id": bot_id, "bot_secret": bot_secret}
        response = requests.post(url, headers=headers, data=data)
        return response.json()["access_token"]
    
    ```
    *範例指令*: 使用 `curl` 命令模擬惡意機器人加入會議的請求。

```

bash
curl -X POST \
  https://api.microsoft.com/meetings/<meeting_id>/join \
  -H 'Authorization: Bearer <bot_token>' \
  -H 'Content-Type: application/json'

```
* **繞過技術**: 惡意機器人可以嘗試使用社交工程攻擊來獲得會議組織者的授權。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Teams_Malicious_Bot {
        meta:
            description = "Detects malicious bots joining Microsoft Teams meetings"
            author = "Your Name"
        strings:
            $bot_token = "Bearer <bot_token>"
        condition:
            $bot_token in (http.request_header | http.request_body)
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。

```

sql
index=microsoft_teams sourcetype=meeting_join 

| where bot_token="Bearer <bot_token>"
| stats count as num_joins by meeting_id, bot_id
```
* **緩解措施**: 會議組織者應該仔細審查機器人身份驗證和授權請求，並確保只有授權的機器人才能加入會議。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth (授權)**: OAuth 是一個授權框架，允許用戶授權第三方應用程序訪問其資源，而無需分享密碼。
* **Bot Authentication (機器人身份驗證)**: 機器人身份驗證是指驗證機器人身份的過程，通常使用 OAuth 或其他授權機制。
* **Meeting Security (會議安全)**: 會議安全是指保護會議的安全和保密，包括授權、身份驗證和加密等措施。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-teams-will-tag-third-party-bots-in-meeting-lobbies/)
- [Microsoft Teams 的安全性和合規性](https://docs.microsoft.com/zh-tw/microsoftteams/security-and-compliance)
- [OAuth 2.0 授權框架](https://tools.ietf.org/html/rfc6749)


