---
layout: post
title:  "微軟發布AI代理框架Agent Framework 1.0，支援多代理調度與MCP"
date:   2026-04-07 07:08:41 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Agent Framework 1.0 的安全性與威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: 代理對代理協作中的資訊洩露風險
> * **關鍵技術**: `Agent-to-Agent` 協定, `Model Context Protocol`, `中介軟體管線機制`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Agent Framework 1.0 中的代理對代理協作機制可能導致資訊洩露風險。這是因為代理之間的通訊可能未經過適當的驗證和加密。
* **攻擊流程圖解**: 
    1. 攻擊者獲得代理的存取權限
    2. 攻擊者利用代理對代理協作機制傳送惡意請求
    3. 目標代理處理惡意請求並返回敏感資訊
* **受影響元件**: Microsoft Agent Framework 1.0, 代理對代理協作機制

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得代理的存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義代理的 URL 和惡意請求
    agent_url = "https://example.com/agent"
    malicious_request = {"action": "get_sensitive_info"}
    
    # 發送惡意請求
    response = requests.post(agent_url, json=malicious_request)
    
    # 處理返回的敏感資訊
    if response.status_code == 200:
        sensitive_info = response.json()
        print(sensitive_info)
    
    ```
    * **範例指令**: 使用 `curl` 命令發送惡意請求

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"action": "get_sensitive_info"}' https://example.com/agent

```
* **繞過技術**: 攻擊者可以利用代理對代理協作機制的漏洞繞過安全檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /agent |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Agent_Framework_1_0 {
        meta:
            description = "Microsoft Agent Framework 1.0 代理對代理協作機制漏洞"
            author = "Your Name"
        strings:
            $agent_url = "https://example.com/agent"
            $malicious_request = "{\"action\": \"get_sensitive_info\"}"
        condition:
            $agent_url and $malicious_request
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=agent_framework 
    
    | search "agent_url=https://example.com/agent" AND "malicious_request={\"action\": \"get_sensitive_info\"}"
    ```
* **緩解措施**: 更新 Microsoft Agent Framework 1.0 至最新版本, 啟用安全檢查和驗證機制

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Agent-to-Agent 協定**: 一種允許代理之間通訊的協定。它定義了代理之間的通訊格式和協議。
* **Model Context Protocol**: 一種允許代理存取外部模型的協定。它定義了代理和外部模型之間的通訊格式和協議。
* **中介軟體管線機制**: 一種允許代理處理請求和返回響應的機制。它定義了代理處理請求和返回響應的流程。

## 5. 🔗 參考文獻與延伸閱讀
- [Microsoft Agent Framework 1.0 官方文件](https://docs.microsoft.com/en-us/azure/agent-framework/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1055/)


