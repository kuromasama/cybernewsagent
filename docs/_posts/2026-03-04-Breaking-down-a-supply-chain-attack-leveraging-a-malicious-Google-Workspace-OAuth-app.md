---
layout: post
title:  "Breaking down a supply chain attack leveraging a malicious Google Workspace OAuth app"
date:   2026-03-04 18:39:46 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Workspace OAuth 攻擊：技術細節與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: OAuth 權限授予攻擊
> * **關鍵技術**: OAuth 2.0、Google Workspace API、權限授予攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 OAuth 2.0 的授權機制，通過欺騙用戶授予不必要的權限，進而獲得對 Google Workspace 資源的存取權。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意的 OAuth 應用程序，並配置為請求高風險的權限（例如 `https://www.googleapis.com/auth/chromewebstore`）。
  2. 攻擊者將用戶導向授權頁面，欺騙用戶授予惡意應用程序權限。
  3. 用戶授予權限後，攻擊者即可使用獲得的權限存取 Google Workspace 資源。
* **受影響元件**: Google Workspace、Google Chrome 瀏覽器

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意的 OAuth 應用程序，並配置為請求高風險的權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意 OAuth 應用程序的 Client ID 和 Client Secret
    client_id = "123456789012-abc123.apps.googleusercontent.com"
    client_secret = "your_client_secret"
    
    # 請求高風險的權限
    scope = "https://www.googleapis.com/auth/chromewebstore"
    
    # 導向授權頁面
    authorization_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&scope={scope}&response_type=code&redirect_uri=http://localhost:8080"
    
    # 使用 curl 導向授權頁面
    curl -X GET "{authorization_url}"
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過 Google 的安全措施，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 136.226.68.203 | example.com | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_oauth_app {
      meta:
        description = "偵測惡意 OAuth 應用程序"
      strings:
        $client_id = "123456789012-abc123.apps.googleusercontent.com"
      condition:
        $client_id in (http.request.uri.query)
    }
    
    ```
* **緩解措施**: 使用 Google Workspace 的安全設定來限制 OAuth 應用程序的權限，並定期審查授權的應用程序。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0**: 一種授權框架，允許用戶授予第三方應用程序存取其資源的權限。
* **Google Workspace API**: Google 提供的一組 API，允許開發者存取 Google Workspace 資源。
* **權限授予攻擊**: 一種攻擊技術，攻擊者通過欺騙用戶授予不必要的權限，進而獲得對資源的存取權。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-detection/google-workspace-oauth-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1556/)


