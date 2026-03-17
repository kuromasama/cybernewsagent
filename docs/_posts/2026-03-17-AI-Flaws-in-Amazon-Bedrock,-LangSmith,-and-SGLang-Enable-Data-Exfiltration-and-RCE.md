---
layout: post
title:  "AI Flaws in Amazon Bedrock, LangSmith, and SGLang Enable Data Exfiltration and RCE"
date:   2026-03-17 18:53:02 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Amazon Bedrock、LangSmith 和 SGLang 的 AI 安全漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：7.5-9.8)
> * **受駭指標**: RCE (Remote Code Execution)、LPE (Local Privilege Escalation) 和 Info Leak
> * **關鍵技術**: DNS Queries、Pickle Deserialization、ZeroMQ Broker

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Amazon Bedrock AgentCore Code Interpreter 的 sandbox 模式允許出站 DNS 查詢，攻擊者可以利用這一點建立命令和控制通道和數據外泄。
* **攻擊流程圖解**:
  1. 攻擊者發送 DNS 查詢到受害者機器。
  2. 受害者機器處理 DNS 查詢並返回結果。
  3. 攻擊者分析返回結果並提取敏感信息。
* **受影響元件**: Amazon Bedrock AgentCore Code Interpreter、LangSmith 和 SGLang。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道受害者機器的 DNS 伺服器地址和受害者機器的 IAM 角色。
* **Payload 建構邏輯**:

    ```
    
    python
    import dns.resolver
    
    # 定義 DNS 伺服器地址
    dns_server = 'example.com'
    
    # 定義受害者機器的 IAM 角色
    iam_role = 'arn:aws:iam::123456789012:role/BedrockAgentCoreCodeInterpreter'
    
    # 建構 DNS 查詢
    query = dns.resolver.query(dns_server, 'TXT')
    
    # 提取返回結果
    result = query.response.answer[0].items[0].to_text()
    
    # 分析返回結果並提取敏感信息
    sensitive_info = result.split(':')[1]
    
    ```
* **繞過技術**: 攻擊者可以使用 DNS 隧道技術繞過防火牆和 IDS/IPS 系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/bedrock_agent_core |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Amazon_Bedrock_AgentCore_Code_Interpreter {
      meta:
        description = "Detects Amazon Bedrock AgentCore Code Interpreter DNS queries"
      strings:
        $dns_query = "example.com"
      condition:
        $dns_query in (dns.query)
    }
    
    ```
* **緩解措施**: 使用 VPC 模式代替 sandbox 模式，實施 DNS 防火牆並過濾出站 DNS 流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DNS 隧道 (DNS Tunneling)**: 一種使用 DNS 協議傳輸非 DNS 數據的技術，常用於繞過防火牆和 IDS/IPS 系統。
* **Pickle Deserialization**: 一種 Python 對象序列化格式，常用於序列化和反序列化 Python 對象。
* **ZeroMQ Broker**: 一種消息隊列系統，常用於實施分布式系統和微服務架構。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/ai-flaws-in-amazon-bedrock-langsmith.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


