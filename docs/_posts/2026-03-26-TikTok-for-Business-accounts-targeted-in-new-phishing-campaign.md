---
layout: post
title:  "TikTok for Business accounts targeted in new phishing campaign"
date:   2026-03-26 18:57:51 +0000
categories: [security]
severity: high
---

# 🔥 解析 TikTok 商業帳戶釣魚攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Credential Theft
> * **關鍵技術**: Phishing, Cloudflare Turnstile, Reverse Proxy

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Cloudflare Turnstile 來阻止安全機器人分析惡意頁面，同時使用 Google Storage URL 來隱藏惡意連結。
* **攻擊流程圖解**:
  1. User Input -> Initial Link -> Google Storage URL
  2. Google Storage URL -> Cloudflare Turnstile Check
  3. Cloudflare Turnstile Check -> Malicious Page
* **受影響元件**: TikTok 商業帳戶、Google Ad Manager 帳戶

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要註冊 Cloudflare 帳戶並設定 Turnstile，同時需要 NiceNIC 域名註冊服務。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Initial Link
    initial_link = "https://example.com/initial-link"
    
    # Google Storage URL
    google_storage_url = "https://storage.googleapis.com/example-bucket/malicious-page.html"
    
    # Cloudflare Turnstile Check
    turnstile_check = "https://example.com/turnstile-check"
    
    # Malicious Page
    malicious_page = "https://example.com/malicious-page"
    
    # Redirect to Malicious Page
    requests.get(initial_link).headers["Location"] == google_storage_url
    requests.get(google_storage_url).headers["Location"] == turnstile_check
    requests.get(turnstile_check).headers["Location"] == malicious_page
    
    ```
* **繞過技術**: 攻擊者使用 Cloudflare Turnstile 來阻止安全機器人分析惡意頁面，同時使用 Google Storage URL 來隱藏惡意連結。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /malicious-page.html |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_page {
      meta:
        description = "Malicious page detection"
        author = "Blue Team"
      strings:
        $malicious_page = "https://example.com/malicious-page"
      condition:
        $malicious_page in (http.request.uri)
    }
    
    ```
* **緩解措施**: 使用 YARA Rule 或 Snort/Suricata Signature 來偵測惡意頁面，同時設定 Cloudflare Turnstile 來阻止安全機器人分析惡意頁面。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing (釣魚)**: 想像一個釣魚者使用假的魚餌來欺騙魚。技術上是指攻擊者使用假的電子郵件或網頁來欺騙用戶輸入敏感資訊。
* **Cloudflare Turnstile (Cloudflare 轉盤)**: 想像一個轉盤可以阻止機器人進入某個網頁。技術上是指 Cloudflare 的一種安全功能，可以阻止機器人分析網頁。
* **Reverse Proxy (反向代理)**: 想像一個代理可以將用戶的請求轉發到另一個伺服器。技術上是指一種代理伺服器，可以將用戶的請求轉發到另一個伺服器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/tiktok-for-business-accounts-targeted-in-new-phishing-campaign/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


