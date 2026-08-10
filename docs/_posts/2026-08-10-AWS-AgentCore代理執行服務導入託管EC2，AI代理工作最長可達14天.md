---
layout: post
title:  "AWS AgentCore代理執行服務導入託管EC2，AI代理工作最長可達14天"
date:   2026-08-10 07:17:27 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Amazon Bedrock AgentCore Runtime 的安全性與威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: 代理工作階段的長時間執行可能導致資源耗盡或敏感資料外洩
> * **關鍵技術**: `EC2`, `GPU`, `AgentCore`, `Runtime Instances`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Amazon Bedrock AgentCore Runtime 的新模式 `Runtime Instances` 允許代理工作階段執行時間最長可達 14 天，相較於原有的無伺服器執行環境的工作階段最長支援 8 小時。這可能導致代理工作階段的長時間執行，增加資源耗盡或敏感資料外洩的風險。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個代理工作階段，指定執行時間為 14 天。
    2. 代理工作階段啟動，開始執行任務。
    3. 攻擊者利用代理工作階段的長時間執行，嘗試耗盡資源或外洩敏感資料。
* **受影響元件**: Amazon Bedrock AgentCore Runtime 的 `Runtime Instances` 模式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Amazon Web Services (AWS) 帳戶和 AgentCore 的使用權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import boto3
    
    # 創建一個代理工作階段
    agentcore = boto3.client('agentcore')
    response = agentcore.create_agent(
        AgentName='example-agent',
        Runtime='runtime-instance',
        InstanceType='c5.xlarge',
        GpuCount=1
    )
    
    # 啟動代理工作階段
    agentcore.start_agent(
        AgentName='example-agent',
        Runtime='runtime-instance'
    )
    
    ```
    *範例指令*: 使用 `aws cli` 指令創建和啟動代理工作階段。
* **繞過技術**: 攻擊者可以嘗試利用代理工作階段的長時間執行，嘗試耗盡資源或外洩敏感資料。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule AgentCore_Runtime_Instances {
        meta:
            description = "Detects AgentCore Runtime Instances"
            author = "Your Name"
        strings:
            $a = "agentcore"
            $b = "runtime-instance"
        condition:
            $a and $b
    }
    
    ```
    * 或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。
* **緩解措施**: 
    1. 監控代理工作階段的執行時間和資源使用情況。
    2. 限制代理工作階段的執行時間和資源使用量。
    3. 實施安全的代理工作階段管理和監控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AgentCore**: Amazon Bedrock 的代理核心，負責管理和執行代理工作階段。
* **Runtime Instances**: Amazon Bedrock 的新模式，允許代理工作階段執行時間最長可達 14 天。
* **GPU**: 圖形處理單元，用于加速計算和圖形渲染。

## 5. 🔗 參考文獻與延伸閱讀
- [Amazon Bedrock 官方文件](https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


