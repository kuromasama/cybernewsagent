---
layout: post
title:  "ConsentFix and ClickFix: How Microsoft 365 Accounts are Hijacked in 3 Seconds"
date:   2026-07-02 19:13:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ConsentFix 與 ClickFix 攻擊：Microsoft 365 會話劫持技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與會話劫持
> * **關鍵技術**: OAuth Consent Flow, Clickjacking, Social Engineering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ConsentFix 攻擊利用了 Microsoft 365 的 OAuth Consent Flow 中的弱點，攻擊者可以透過精心設計的 phishing 頁面，誘使用戶將 localhost callback 連結拖放到瀏覽器中，從而取得 OAuth Token，並劫持用戶的 Microsoft 365 會話。
* **攻擊流程圖解**:
  1. 攻擊者發送 phishing 郵件或訊息，包含一個看似合法的 Microsoft 365 驗證頁面連結。
  2. 用戶點擊連結，出現一個假的 Microsoft 365 驗證頁面，要求用戶將 localhost callback 連結拖放到瀏覽器中。
  3. 用戶拖放連結，攻擊者取得 OAuth Token，並劫持用戶的 Microsoft 365 會話。
* **受影響元件**: Microsoft 365、OAuth 2.0

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個合法的 Microsoft 365 帳戶，並能夠發送 phishing 郵件或訊息。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建立一個假的 Microsoft 365 驗證頁面
    def create_phishing_page():
        # ...
        return phishing_page
    
    # 發送 phishing 郵件或訊息
    def send_phishing_message(phishing_page):
        # ...
        return
    
    # 取得 OAuth Token
    def get_oauth_token():
        # ...
        return oauth_token
    
    # 劫持用戶的 Microsoft 365 會話
    def hijack_session(oauth_token):
        # ...
        return
    
    ```
* **繞過技術**: 攻擊者可以使用 Social Engineering 技術，例如使用看似合法的郵件或訊息，來誘使用戶點擊連結。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ConsentFix {
        meta:
            description = "Detects ConsentFix attacks"
            author = "Your Name"
        strings:
            $phishing_page = "https://example.com/phishing-page"
        condition:
            $phishing_page in (http.request.uri)
    }
    
    ```
* **緩解措施**: 用戶應該避免點擊來自未知來源的連結，並在瀏覽器中啟用 OAuth 2.0 的安全功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0**: 一種授權框架，允許用戶授權第三方應用程式存取其資源。
* **Clickjacking**: 一種攻擊技術，透過誘使用戶點擊一個看似合法的按鈕或連結，來取得授權或執行惡意代碼。
* **Social Engineering**: 一種攻擊技術，透過心理操縱，來誘使用戶執行某些動作或提供敏感資訊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/consentfix-and-clickfix-how-microsoft-365-accounts-are-hijacked-in-3-seconds/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


