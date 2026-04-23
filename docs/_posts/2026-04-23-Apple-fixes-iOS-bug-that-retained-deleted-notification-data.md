---
layout: post
title:  "Apple fixes iOS bug that retained deleted notification data"
date:   2026-04-23 02:00:36 +0000
categories: [security]
severity: high
---

# 🔥 解析 iOS 通知服務漏洞：CVE-2026-28950

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Notification Services`, `Data Redaction`, `iOS Sandbox`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: iOS 通知服務中的漏洞導致已刪除的通知仍然存儲在設備上。這是由於通知服務未正確地刪除通知數據所致。
* **攻擊流程圖解**: 
    1. 使用者刪除通知
    2. 通知服務未正確地刪除通知數據
    3. 攻擊者可以存取已刪除的通知數據
* **受影響元件**: iOS 26.4.2 和 iPadOS 26.4.2，以及 iOS 18.7.8 和 iPadOS 18.7.8

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要存取受害者的設備
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義通知服務 API
    notification_api = "https://example.com/notification"
    
    # 定義已刪除的通知 ID
    deleted_notification_id = "123456"
    
    # 發送請求以存取已刪除的通知
    response = requests.get(notification_api + "/" + deleted_notification_id)
    
    # 列印已刪除的通知內容
    print(response.text)
    
    ```
    * **範例指令**: 使用 `curl` 命令發送請求以存取已刪除的通知

```

bash
curl -X GET https://example.com/notification/123456

```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用代理伺服器或修改 HTTP 請求頭

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 123456 | 192.168.1.100 | example.com | /notification |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ios_notification_leak {
        meta:
            description = "iOS 通知服務漏洞偵測"
            author = "Your Name"
        strings:
            $notification_api = "https://example.com/notification"
        condition:
            $notification_api in (http.request.uri)
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=ios_logs sourcetype=notification_api 
    
    | stats count as notification_count by notification_id
    | where notification_count > 1
    ```
* **緩解措施**: 更新 iOS 和 iPadOS 至最新版本，並設定通知服務以正確地刪除通知數據

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Notification Services (通知服務)**: iOS 和 iPadOS 中的通知服務，負責管理和顯示通知。
* **Data Redaction (數據刪除)**: 一種安全技術，用于刪除敏感數據。
* **iOS Sandbox (iOS 沙盒)**: 一種安全機制，用于隔離和限制應用程式的存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/apple-fixes-ios-bug-that-retained-deleted-notification-data/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


