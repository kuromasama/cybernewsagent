---
layout: post
title:  "Google Chrome now lets you turn off on-device AI model powering scam detection"
date:   2026-01-18 02:42:10 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Google Chrome AI 驅動的增強保護機制與潛在風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `AI 驅動的增強保護`, `On-device GenAI`, `Chrome Canary`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Chrome 的 AI 驅動的增強保護機制使用了本地 AI 模型來實現實時保護，然而這個機制可能會導致資訊洩露。
* **攻擊流程圖解**: 
    1. 使用者啟用 AI 驅動的增強保護
    2. Chrome 下載並安裝本地 AI 模型
    3. 攻擊者利用漏洞存取本地 AI 模型
    4. 攻擊者分析本地 AI 模型以獲取敏感資訊
* **受影響元件**: Google Chrome Canary 版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Chrome Canary 版本的存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載本地 AI 模型
    response = requests.get("https://example.com/ai_model")
    with open("ai_model", "wb") as f:
        f.write(response.content)
    
    # 分析本地 AI 模型
    with open("ai_model", "rb") as f:
        ai_model = f.read()
        # 對 ai_model 進行分析以獲取敏感資訊
    
    ```
    *範例指令*: 使用 `curl` 下載本地 AI 模型

```

bash
curl -o ai_model https://example.com/ai_model

```
* **繞過技術**: 攻擊者可以利用 WAF 或 EDR 繞過技巧來隱藏自己的行為

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /ai_model |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Chrome_Ai_Model {
        meta:
            description = "Detects Chrome AI model"
            author = "Your Name"
        strings:
            $ai_model = "AI model data"
        condition:
            $ai_model
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)

```

sql
index=chrome_logs | search "ai_model"

```
* **緩解措施**: 除了更新修補之外，使用者可以關閉 AI 驅動的增強保護功能

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **On-device GenAI**: 想像一台可以在本地運行 AI 模型的裝置。技術上是指在用戶的裝置上運行 AI 模型，以實現實時保護。
* **AI 驅動的增強保護**: 想像一種可以自動學習和適應的保護機制。技術上是指使用 AI 模型來實現實時保護，例如偵測惡意網站和下載。
* **Chrome Canary**: 想像一種可以測試最新功能的瀏覽器版本。技術上是指 Google Chrome 的 Canary 版本，是用於測試最新功能和修補的版本。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/artificial-intelligence/google-chrome-now-lets-you-turn-off-on-device-ai-model-powering-scam-detection/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1056/)


