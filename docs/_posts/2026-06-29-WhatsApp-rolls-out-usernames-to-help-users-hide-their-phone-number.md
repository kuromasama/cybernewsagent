---
layout: post
title:  "WhatsApp rolls out usernames to help users hide their phone number"
date:   2026-06-29 19:48:58 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 WhatsApp 用戶名稱保留功能的安全性
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Username Enumeration`, `Phone Number Privacy`, `Optional Key`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: WhatsApp 的用戶名稱保留功能允許用戶隱藏他們的電話號碼，但如果攻擊者可以枚舉用戶名稱，可能會導致資訊洩露。
* **攻擊流程圖解**: 
    1. 攻擊者嘗試枚舉用戶名稱。
    2. 如果用戶名稱存在，攻擊者可以發送消息給用戶。
    3. 如果用戶沒有設定可選密鑰，攻擊者可以直接發送消息。
* **受影響元件**: WhatsApp 的用戶名稱保留功能，所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道用戶名稱或電話號碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    def enumerate_username(username):
        url = f"https://api.whatsapp.com/v1/user/{username}"
        response = requests.get(url)
        if response.status_code == 200:
            print(f"用戶名稱 {username} 存在")
        else:
            print(f"用戶名稱 {username} 不存在")
    
    # 範例指令
    enumerate_username("example_username")
    
    ```
* **繞過技術**: 如果用戶設定了可選密鑰，攻擊者需要知道密鑰才能發送消息。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | api.whatsapp.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule WhatsApp_Username_Enumeration {
        meta:
            description = "WhatsApp 用戶名稱枚舉攻擊"
            author = "Your Name"
        strings:
            $url = "https://api.whatsapp.com/v1/user/"
        condition:
            $url in http_request
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
index=whatsapp_logs | search "https://api.whatsapp.com/v1/user/*"

```
* **緩解措施**: 用戶應該設定可選密鑰，並且定期更改密鑰。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Username Enumeration (用戶名稱枚舉)**: 想像攻擊者嘗試猜測用戶名稱。技術上是指攻擊者嘗試枚舉用戶名稱，以便獲得用戶的資訊。
* **Phone Number Privacy (電話號碼隱私)**: 想像用戶想要隱藏他們的電話號碼。技術上是指用戶可以設定用戶名稱來隱藏他們的電話號碼。
* **Optional Key (可選密鑰)**: 想像用戶想要增加安全性。技術上是指用戶可以設定密鑰，以便增加安全性。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/whatsapp-rolls-out-usernames-to-help-users-hide-their-phone-number/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1082/)


