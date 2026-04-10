---
layout: post
title:  "Microsoft: Canadian employees targeted in payroll pirate attacks"
date:   2026-04-10 12:56:02 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Storm-2755 攻擊：利用 AiTM 繞過 MFA 防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Authentication Bypass
> * **關鍵技術**: Adversary-in-the-Middle (AiTM), Malicious Microsoft 365 Sign-in Pages, Session Cookie Theft

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Storm-2755 攻擊者利用 AiTM 技術，透過惡意的 Microsoft 365 登入頁面，竊取使用者的驗證令牌和會話 Cookie。這使得攻擊者可以繞過多因素驗證 (MFA) 機制，直接存取受害者的帳戶。
* **攻擊流程圖解**:
  1. 使用者訪問惡意的 Microsoft 365 登入頁面。
  2. 使用者輸入帳戶密碼和驗證碼。
  3. 惡意頁面竊取使用者的驗證令牌和會話 Cookie。
  4. 攻擊者使用竊取的令牌和 Cookie，繞過 MFA 機制，直接存取受害者的帳戶。
* **受影響元件**: Microsoft 365、Workday、HR 軟件平台

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有能力將惡意的 Microsoft 365 登入頁面推廣到搜索引擎的首頁，或是通過其他手段將使用者導向惡意頁面。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意頁面代碼範例
      import requests
    
      def steal_session_cookie():
        #竊取使用者的會話 Cookie
        cookie = requests.get('https://example.com/login').cookies
        return cookie
    
      def bypass_mfa(cookie):
        #使用竊取的 Cookie 繞過 MFA 機制
        headers = {'Cookie': cookie}
        response = requests.get('https://example.com/protected', headers=headers)
        return response.text
    
    ```
* **繞過技術**: Storm-2755 攻擊者使用 AiTM 技術，透過惡意的 Microsoft 365 登入頁面，竊取使用者的驗證令牌和會話 Cookie，繞過 MFA 機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Storm_2755 {
        meta:
          description = "Storm-2755 攻擊偵測"
          author = "Your Name"
        strings:
          $cookie_steal = "steal_session_cookie"
          $mfa_bypass = "bypass_mfa"
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 封鎖惡意的 Microsoft 365 登入頁面，實施 phishing-resistant MFA 機制，定期更新和修補系統漏洞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Adversary-in-the-Middle (AiTM)**: 惡意的中間人攻擊，攻擊者竊取使用者的驗證令牌和會話 Cookie，繞過 MFA 機制。
* **Session Cookie**: 會話 Cookie 是用於存儲使用者會話信息的 Cookie，攻擊者可以竊取這些 Cookie 來繞過 MFA 機制。
* **Phishing-resistant MFA**: 抵禦釣魚攻擊的 MFA 機制，使用者需要提供額外的驗證信息，例如生物特徵或 U2F 密鑰。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-canadian-employees-targeted-in-payroll-pirate-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/)


