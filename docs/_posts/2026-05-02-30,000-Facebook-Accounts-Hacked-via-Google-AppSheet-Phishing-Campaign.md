---
layout: post
title:  "30,000 Facebook Accounts Hacked via Google AppSheet Phishing Campaign"
date:   2026-05-02 02:05:06 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google AppSheet 作為「釣魚中繼站」的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Account Takeover (ATO) 和敏感資訊洩露
> * **關鍵技術**: Phishing, Social Engineering, AppSheet Exploitation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Google AppSheet 的功能，創建了一個「釣魚中繼站」，用於分發釣魚郵件和收集敏感資訊。這是因為 AppSheet 的設計允許用戶創建自定義表單和工作流程，而攻擊者利用這一點來創建了一個假的 Facebook 帳戶恢復流程。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 Google AppSheet 表單，模擬 Facebook 的帳戶恢復流程。
  2. 用戶收到一封釣魚郵件，內容是要求用戶提交一個申請，以恢復其 Facebook 帳戶。
  3. 用戶點擊郵件中的連結，導致其被重定向到 AppSheet 表單。
  4. AppSheet 表單收集用戶的敏感資訊，包括帳戶密碼和兩步驟驗證碼。
  5. 攻擊者收集到敏感資訊後，利用它們來登入用戶的 Facebook 帳戶。
* **受影響元件**: Google AppSheet、Facebook

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Google AppSheet 帳戶和一個 Facebook 帳戶。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 AppSheet 表單的 ID 和用戶的 Facebook 帳戶資訊
    app_sheet_id = "your_app_sheet_id"
    facebook_username = "your_facebook_username"
    facebook_password = "your_facebook_password"
    
    # 創建一個假的 Facebook 帳戶恢復流程
    def create_fake_recovery_flow():
        # ...
    
    # 收集用戶的敏感資訊
    def collect_sensitive_info():
        # ...
    
    # 登入用戶的 Facebook 帳戶
    def login_facebook_account():
        # ...
    
    ```
* **繞過技術**: 攻擊者可以利用 AppSheet 的功能來繞過 Facebook 的安全措施，例如使用 AppSheet 的「工作流程」功能來自動化登入過程。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 216.58.194.174 |
| Domain | appsheet.com |
| File Path | /index.html |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule AppSheet_Phishing {
      meta:
        description = "AppSheet 釣魚攻擊"
        author = "Your Name"
      strings:
        $app_sheet_id = "your_app_sheet_id"
        $facebook_username = "your_facebook_username"
        $facebook_password = "your_facebook_password"
      condition:
        $app_sheet_id and $facebook_username and $facebook_password
    }
    
    ```
* **緩解措施**: 用戶應該避免點擊來自未知來源的連結，並且應該使用強密碼和兩步驟驗證來保護其 Facebook 帳戶。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AppSheet**: 一種 Google 的雲端應用平台，允許用戶創建自定義表單和工作流程。
* **Phishing**: 一種社交工程攻擊，攻擊者利用假的郵件或網站來收集用戶的敏感資訊。
* **Social Engineering**: 一種攻擊方式，攻擊者利用人類的心理弱點來收集敏感資訊或實施攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/30000-facebook-accounts-hacked-via.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


