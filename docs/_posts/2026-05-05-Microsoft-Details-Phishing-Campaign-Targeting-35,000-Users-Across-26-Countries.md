---
layout: post
title:  "Microsoft Details Phishing Campaign Targeting 35,000 Users Across 26 Countries"
date:   2026-05-05 07:59:16 +0000
categories: [security]
severity: critical
---

# 🚨 解析大規模憑證竊取攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credential Harvesting
> * **關鍵技術**: Phishing, CAPTCHA, Adversary-in-the-Middle (AiTM)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用合法的電子郵件服務和精心設計的電子郵件模板，欺騙用戶點擊連結並輸入憑證。
* **攻擊流程圖解**:
  1. 攻擊者發送電子郵件給用戶，內容包含「行為準則審查」等主題。
  2. 用戶點擊電子郵件中的連結，導致用戶被導向攻擊者控制的網站。
  3. 網站要求用戶輸入憑證，攻擊者使用Adversary-in-the-Middle (AiTM)技術竊取憑證。
* **受影響元件**: Microsoft 365、Azure Active Directory (AAD)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要合法的電子郵件服務和精心設計的電子郵件模板。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義電子郵件模板
    email_template = """
    <html>
      <body>
        <h1>行為準則審查</h1>
        <p>請點擊以下連結進行審查：<a href="https://example.com">連結</a></p>
      </body>
    </html>
    """
    
    # 定義攻擊者控制的網站
    def attack_website():
      # 要求用戶輸入憑證
      username = input("請輸入用戶名：")
      password = input("請輸入密碼：")
      # 竊取憑證
      print("憑證已竊取：", username, password)
    
    # 發送電子郵件
    def send_email():
      # 使用合法的電子郵件服務
      email_service = "example@example.com"
      # 發送電子郵件
      requests.post("https://example.com/send_email", data={"email": email_template})
    
    # 執行攻擊
    send_email()
    attack_website()
    
    ```
* **繞過技術**: 攻擊者使用CAPTCHA和中間頁面來繞過自動化防禦。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule phishing_email {
      meta:
        description = "偵測電子郵件釣魚攻擊"
        author = "example"
      strings:
        $email_template = { 48 65 6c 6c 6f 20 57 6f 72 6c 64 21 }
      condition:
        $email_template at 0
    }
    
    ```
* **緩解措施**: 更新Microsoft 365和Azure Active Directory (AAD)的安全更新，啟用多因素驗證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing (電子郵件釣魚)**: 攻擊者通過電子郵件欺騙用戶輸入敏感信息。
* **CAPTCHA (完全自動化的區分計算機和人類的圖靈測試)**: 一種挑戰-反應測試，要求用戶完成特定任務以證明其為人類。
* **Adversary-in-the-Middle (AiTM) (中間人攻擊)**: 攻擊者在用戶和服務器之間插入自己，竊取敏感信息。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/microsoft-details-phishing-campaign.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


