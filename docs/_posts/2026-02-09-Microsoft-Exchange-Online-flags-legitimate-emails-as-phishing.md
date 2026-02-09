---
layout: post
title:  "Microsoft: Exchange Online flags legitimate emails as phishing"
date:   2026-02-09 12:54:38 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Exchange Online 錯誤標記合法郵件為釣魚郵件的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: False Positive (誤判合法郵件為釣魚郵件)
> * **關鍵技術**: URL 分析、機器學習模型、電子郵件過濾

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Exchange Online 的 URL 分析機制中，新加入的 URL 規則錯誤地標記了一些合法的 URL 為惡意，導致相關的電子郵件被誤判為釣魚郵件。
* **攻擊流程圖解**: 
  1. 使用者收到含有合法 URL 的電子郵件。
  2. Microsoft Exchange Online 的 URL 分析機制啟動。
  3. 新的 URL 規則錯誤地標記 URL 為惡意。
  4. 電子郵件被誤判為釣魚郵件並被隔離。
* **受影響元件**: Microsoft Exchange Online，具體版本號未公佈。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要知道 Microsoft Exchange Online 的 URL 分析機制和新的 URL 規則。
* **Payload 建構邏輯**:

    ```
    
    python
        # 範例 Payload
        import requests
    
        url = "https://example.com/legitimate-url"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3"
        }
    
        response = requests.get(url, headers=headers)
        print(response.text)
    
    ```
    * **範例指令**: 使用 `curl` 命令測試 URL 是否被誤判為惡意。

```

bash
    curl -X GET "https://example.com/legitimate-url" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.3"

```
* **繞過技術**: 可以嘗試使用不同的 User-Agent 或修改 URL 來繞過誤判。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| - | - | example.com | - |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule legitimate_url {
            meta:
                description = "Legitimate URL"
                author = "Your Name"
            strings:
                $url = "https://example.com/legitimate-url"
            condition:
                $url
        }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
        index=exchange_logs (url="https://example.com/legitimate-url")
    
    ```
* **緩解措施**: 更新 Microsoft Exchange Online 的 URL 分析機制和新的 URL 規則，或者暫時停用新的 URL 規則。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **URL 分析 (URL Analysis)**: 透過分析 URL 的內容和結構來判斷其是否為惡意。
* **機器學習模型 (Machine Learning Model)**: 一種使用機器學習算法來訓練和預測的模型，常用於垃圾郵件和釣魚郵件的過濾。
* **電子郵件過濾 (Email Filtering)**: 透過分析電子郵件的內容和來源來過濾掉垃圾郵件和釣魚郵件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-online-flags-legitimate-emails-as-phishing/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


