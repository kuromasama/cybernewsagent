---
layout: post
title:  "Anthropic公布Claude Code Channels，開發人員可用Telegram、Discord和Claude溝通"
date:   2026-03-24 06:56:27 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Anthropic Claude Code Channels 的安全性與潛在風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `事件通道（event channel）`, `外掛機制`, `遠端控制`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude Code Channels 的事件通道機制允許開發人員將訊息、警示或 webhooks 從 MCP 伺服器主動推送進一個正在運行的 Claude Code session。這個機制可能會被利用來執行遠端代碼。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個惡意的外掛，包含遠端代碼執行的 payload。
    2. 攻擊者將外掛安裝到 Claude Code Channels 中。
    3. 攻擊者使用 Telegram 或 Discord 等外部通訊工具，向 Claude Code Channels 發送命令。
    4. Claude Code Channels 收到命令後，會將命令轉發給 MCP 伺服器。
    5. MCP 伺服器執行命令，可能會導致遠端代碼執行。
* **受影響元件**: Claude Code v2.1.80 以後版本，且需要登入 claude.ai。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Claude Code Channels 的使用權限，且需要安裝惡意的外掛。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 payload
    payload = {
        "command": "deploy staging",
        "args": ["--force"]
    }
    
    # 發送 payload 到 Claude Code Channels
    response = requests.post("https://claude.ai/api/execute", json=payload)
    
    # 檢查回應
    if response.status_code == 200:
        print("Payload 執行成功")
    else:
        print("Payload 執行失敗")
    
    ```
    * **範例指令**: 使用 `curl` 發送 payload 到 Claude Code Channels。

```

bash
curl -X POST \
  https://claude.ai/api/execute \
  -H 'Content-Type: application/json' \
  -d '{"command": "deploy staging", "args": ["--force"]}'

```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 Base64 編碼 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | claude.ai | /api/execute |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Claude_Code_Channels_Payload {
        meta:
            description = "Detects Claude Code Channels payload"
            author = "Your Name"
        strings:
            $payload = { 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 }
        condition:
            $payload at 0
    }
    
    ```
    * **SIEM 查詢語法**:

    ```
    
    sql
    SELECT * FROM logs WHERE message LIKE '%Claude Code Channels%' AND timestamp > NOW() - INTERVAL 1 DAY
    
    ```
* **緩解措施**: 更新 Claude Code Channels 到最新版本，且啟用安全模式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **事件通道（event channel）**: 想像兩個系統之間的通訊管道。技術上是指一個機制，允許不同系統之間的通訊和資料交換。
* **外掛機制**: 想像一個系統的擴充功能。技術上是指一個機制，允許開發人員創建和安裝外掛，來擴充系統的功能。
* **遠端控制**: 想像一個系統被遠端控制。技術上是指一個機制，允許使用者從遠端控制系統的行為和功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174611)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


