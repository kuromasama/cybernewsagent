---
layout: post
title:  "Critical TeamCity Flaw Could Let Attackers Run OS Commands Without Logging In"
date:   2026-07-28 13:47:43 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamCity 遠程命令執行漏洞：CVE-2026-63077
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Deserialization`, `Agent Polling Protocol`, `Unauthenticated Access`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 TeamCity 的 agent polling protocol 中的 deserialization 處理過程中沒有正確驗證使用者身份，導致未經驗證的使用者可以執行任意系統命令。
* **攻擊流程圖解**: 
    1. 攻擊者發送特製的 HTTP 請求到 TeamCity 伺服器。
    2. TeamCity 伺服器接收請求並進行 deserialization 處理。
    3. 未經驗證的使用者可以利用 deserialization 處理過程中的漏洞，執行任意系統命令。
* **受影響元件**: 所有 TeamCity On-Premises 版本，已在版本 2025.11.7 和 2026.1.3 中修復。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要對 TeamCity 伺服器具有 HTTP(S) 存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 payload
    payload = {
        # 特製的 deserialization payload
    }
    
    # 發送請求
    response = requests.post('https://teamcity-server.com/agentPolling', json=payload)
    
    # 驗證是否成功執行任意命令
    if response.status_code == 200:
        print("成功執行任意命令")
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用特製的 HTTP 請求方法或 header。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule TeamCity_RCE {
        meta:
            description = "TeamCity RCE Detection"
            author = "Your Name"
        condition:
            // 特製的 deserialization payload
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)：

```

sql
index=teamcity_logs | search "agentPolling" AND "deserialization"

```
* **緩解措施**: 更新 TeamCity 伺服器到最新版本，或者安裝安全補丁插件。另外，建議使用 VPN 連接或實施額外的安全措施以防止未經驗證的使用者存取 TeamCity 伺服器。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 想像將一個物件轉換成字串的過程。技術上是指將資料從字串或其他格式轉換回原始的物件或結構。
* **Agent Polling Protocol (代理輪詢協議)**: TeamCity 使用的協議，允許代理程式與伺服器進行通信。
* **Unauthenticated Access (未經驗證的存取)**: 未經驗證的使用者可以存取系統或資料的狀態。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/critical-teamcity-flaw-could-let.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


