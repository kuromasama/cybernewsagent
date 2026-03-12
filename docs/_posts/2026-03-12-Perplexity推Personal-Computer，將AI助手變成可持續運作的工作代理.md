---
layout: post
title:  "Perplexity推Personal Computer，將AI助手變成可持續運作的工作代理"
date:   2026-03-12 06:45:09 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Perplexity AI 服務的安全性與潛在風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: 信息洩露（Info Leak）
> * **關鍵技術**: `API`, `AI`, `代理式系統`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Perplexity AI 服務的代理式系統可能存在信息洩露風險，因為它可以連接多個資料來源和應用程式。
* **攻擊流程圖解**: 
  1. 攻擊者獲得 Perplexity AI 服務的授權。
  2. 攻擊者使用 Perplexity AI 服務的 API 連接到敏感資料來源。
  3. 攻擊者利用 Perplexity AI 服務的代理式系統存取和操控敏感資料。
* **受影響元件**: Perplexity AI 服務的所有版本，特別是 Computer 和 Comet Enterprise。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Perplexity AI 服務的授權和敏感資料來源的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 Perplexity AI 服務的 API 端點
    api_endpoint = "https://api.perplexity.ai/computer"
    
    # 定義敏感資料來源的 API 端點
    data_source_endpoint = "https://api.datasourcemanager.com/data"
    
    # 建構 Payload
    payload = {
        "query": "SELECT * FROM sensitive_data",
        "data_source": data_source_endpoint
    }
    
    # 發送請求到 Perplexity AI 服務的 API
    response = requests.post(api_endpoint, json=payload)
    
    # 處理響應
    if response.status_code == 200:
        print("攻擊成功")
    else:
        print("攻擊失敗")
    
    ```
* **繞過技術**: 攻擊者可以利用 Perplexity AI 服務的代理式系統繞過安全控制，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | perplexity.ai | /computer/api |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule perplexity_ai_attack {
        meta:
            description = "Perplexity AI 服務攻擊"
            author = "Blue Team"
        strings:
            $api_endpoint = "https://api.perplexity.ai/computer"
            $data_source_endpoint = "https://api.datasourcemanager.com/data"
        condition:
            $api_endpoint and $data_source_endpoint
    }
    
    ```
* **緩解措施**: 
  1. 更新 Perplexity AI 服務到最新版本。
  2. 啟用安全控制，例如 IP 白名單和 API 金鑰驗證。
  3. 監控 Perplexity AI 服務的 API 請求和響應。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **代理式系統 (Agent-based System)**: 一種軟體系統，使用代理程式來代表使用者或其他系統，執行任務和交互。
* **API (Application Programming Interface)**: 一種軟體介面，允許不同應用程式之間的交互和資料交換。
* **AI (Artificial Intelligence)**: 一種軟體技術，模擬人類的智慧和學習能力，應用於各種領域。

## 5. 🔗 參考文獻與延伸閱讀
- [Perplexity AI 官方網站](https://www.perplexity.ai/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


