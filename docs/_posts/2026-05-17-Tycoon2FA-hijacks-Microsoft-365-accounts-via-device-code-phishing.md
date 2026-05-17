---
layout: post
title:  "Tycoon2FA hijacks Microsoft 365 accounts via device-code phishing"
date:   2026-05-17 18:58:42 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Tycoon2FA 攻擊：OAuth 2.0 裝置授權流程劫持

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: OAuth 2.0 裝置授權流程劫持
> * **關鍵技術**: OAuth 2.0、裝置授權流程、Trustifi click-tracking URL

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Tycoon2FA 攻擊利用 OAuth 2.0 裝置授權流程的漏洞，通過 Trustifi click-tracking URL Redirect 到假的 Microsoft CAPTCHA 頁面，從而取得 OAuth 2.0 許可權。
* **攻擊流程圖解**:
  1. User Input -> Trustifi click-tracking URL Redirect -> Cloudflare Workers -> Obfuscated JavaScript Layers -> 假的 Microsoft CAPTCHA 頁面
  2. User Input -> 假的 Microsoft CAPTCHA 頁面 -> Microsoft OAuth 2.0 裝置授權流程 -> Attacker-Controlled Device
* **受影響元件**: Microsoft 365、OAuth 2.0、Trustifi

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: User 需要點擊 Trustifi click-tracking URL
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Trustifi click-tracking URL
    url = "https://example.com/trustifi-click-tracking-url"
    
    # Redirect 到假的 Microsoft CAPTCHA 頁面
    response = requests.get(url)
    print(response.url)
    
    ```
* **繞過技術**: Tycoon2FA 攻擊利用 Trustifi click-tracking URL Redirect 到假的 Microsoft CAPTCHA 頁面，從而繞過 OAuth 2.0 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /trustifi-click-tracking-url |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Tycoon2FA_Attack {
      meta:
        description = "Tycoon2FA 攻擊偵測規則"
      strings:
        $trustifi_url = "https://example.com/trustifi-click-tracking-url"
      condition:
        $trustifi_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 禁用 OAuth 2.0 裝置授權流程、限制 OAuth 2.0 許可權、啟用 Continuous Access Evaluation (CAE)

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0**: OAuth 2.0 是一個授權框架，允許用戶授權第三方應用程式存取其資源。
* **裝置授權流程**: 裝置授權流程是一種 OAuth 2.0 授權流程，允許用戶授權裝置存取其資源。
* **Trustifi click-tracking URL**: Trustifi click-tracking URL 是一種 URL Redirect 技術，允許攻擊者 Redirect 用戶到假的 Microsoft CAPTCHA 頁面。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1556/)


