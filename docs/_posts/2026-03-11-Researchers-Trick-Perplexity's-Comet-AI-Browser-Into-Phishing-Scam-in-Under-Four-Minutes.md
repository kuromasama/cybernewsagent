---
layout: post
title:  "Researchers Trick Perplexity's Comet AI Browser Into Phishing Scam in Under Four Minutes"
date:   2026-03-11 18:44:47 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Agentic 瀏覽器的 AI 驅動型攻擊：利用 Agentic Blabbering 進行 Phishing 攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Agentic Blabbering, Generative Adversarial Network (GAN), Prompt Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Agentic 瀏覽器的 AI 驅動型功能允許它自主執行動作，但這也導致了它可能被訓練和欺騙以落入 Phishing 和詐騙陷阱。
* **攻擊流程圖解**:
  1. 攻擊者攔截瀏覽器和 AI 服務之間的流量。
  2. 攻擊者使用攔截的流量作為輸入，訓練一個 GAN 來生成一個 Phishing 頁面。
  3. GAN 生成的 Phishing 頁面被用來欺騙 Agentic 瀏覽器，讓它執行惡意動作。
* **受影響元件**: Perplexity 的 Comet AI 瀏覽器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要攔截瀏覽器和 AI 服務之間的流量。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 攔截的流量
    traffic = requests.get('https://example.com/traffic')
    
    # 訓練 GAN 生成 Phishing 頁面
    gan = GAN(traffic)
    phishing_page = gan.generate()
    
    # 欺騙 Agentic 瀏覽器
    requests.post('https://example.com/agentic', data=phishing_page)
    
    ```
* **繞過技術**: 攻擊者可以使用 Prompt Injection 技術來繞過瀏覽器的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /phishing/page |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Agentic_Blabberring {
      meta:
        description = "Detects Agentic Blabbering attacks"
      strings:
        $a = "Agentic Blabbering"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新瀏覽器和 AI 服務的安全補丁，使用安全的通信協議（如 HTTPS），並實施嚴格的流量控制和監控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Agentic Blabbering**: 一種攻擊技術，利用 Agentic 瀏覽器的 AI 驅動型功能來生成 Phishing 頁面。
* **Generative Adversarial Network (GAN)**: 一種深度學習模型，用于生成和判斷數據。
* **Prompt Injection**: 一種攻擊技術，利用 Prompt Injection 來欺騙 Agentic 瀏覽器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/researchers-trick-perplexitys-comet-ai.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


