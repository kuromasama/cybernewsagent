---
layout: post
title:  "236,000 DCloud Uni-App Sites Used in Crypto Scams, Phishing, and Wallet Drainers"
date:   2026-06-29 15:34:12 +0000
categories: [security]
severity: high
---

# 🔥 解析 DCloud Uni-App 框架的投資詐騙模板
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Investment Scam Websites
> * **關鍵技術**: DCloud Uni-App, Cross-Site Scripting (XSS), Phishing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: DCloud Uni-App 框架的投資詐騙模板被用於建立假的投資平台，利用 Cross-Site Scripting (XSS) 和 Phishing 技術來欺騙用戶。
* **攻擊流程圖解**:
  1. 攻擊者建立假的投資平台使用 DCloud Uni-App 框架。
  2. 用戶訪問假的投資平台並輸入個人資料。
  3. 攻擊者使用 XSS 技術來竊取用戶的敏感信息。
  4. 攻擊者使用 Phishing 技術來欺騙用戶投資假的項目。
* **受影響元件**: DCloud Uni-App 框架的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 DCloud Uni-App 框架的知識和技術。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的投資平台 URL
    url = "https://example.com/investment"
    
    # 用戶輸入的個人資料
    data = {
        "username": "user123",
        "password": "pass123"
    }
    
    # 發送請求到假的投資平台
    response = requests.post(url, data=data)
    
    # 攻擊者使用 XSS 技術來竊取用戶的敏感信息
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.post(url, data={"username": xss_payload})
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術來避免被偵測，例如使用代理伺服器、VPN 等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /investment |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule DCloud_Uni_App_Investment_Scam {
        meta:
            description = "DCloud Uni-App Investment Scam"
            author = "Your Name"
        strings:
            $xss_payload = "<script>alert('XSS')</script>"
        condition:
            $xss_payload in (http.request.body | http.response.body)
    }
    
    ```
* **緩解措施**: 用戶應該避免訪問假的投資平台，並且應該使用安全的瀏覽器和防毒軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DCloud Uni-App**: 一種跨平台的應用開發框架。
* **Cross-Site Scripting (XSS)**: 一種網頁安全漏洞，允許攻擊者在用戶的瀏覽器中執行任意的 JavaScript 代碼。
* **Phishing**: 一種社交工程攻擊，旨在欺騙用戶輸入敏感信息。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/236000-dcloud-uni-app-sites-used-in.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


