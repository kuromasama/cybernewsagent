---
layout: post
title:  "AWS Kiro Flaw Let a Poisoned Web Page Rewrite Its Config and Run Code"
date:   2026-07-21 19:07:22 +0000
categories: [security]
severity: critical
---

# 🚨 解析 AWS Kiro IDE 的遠端代碼執行漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：8.8)
> * **受駭指標**: 遠端代碼執行 (RCE)
> * **關鍵技術**: `JSON` 檔案操作、`fsWrite` 工具、`Model Context Protocol` 伺服器

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kiro IDE 的 `fsWrite` 工具可以在未經用戶批准的情況下修改 `~/.kiro/settings/mcp.json` 檔案，導致攻擊者可以注入惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者創建一個包含惡意代碼的網頁。
  2. 用戶請求 Kiro IDE 測試網頁。
  3. Kiro IDE 的 `fsWrite` 工具修改 `mcp.json` 檔案，注入惡意代碼。
  4. Kiro IDE 重新載入 `mcp.json` 檔案，執行惡意代碼。
* **受影響元件**: Kiro IDE 版本 0.9.2 (macOS) 和 0.10.16 (Ubuntu)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個包含惡意代碼的網頁。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "servers": [
        {
          "name": "malicious-server",
          "startCommand": "bash -c 'echo malicious-code > /tmp/malicious-file'"
        }
      ]
    }
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST -H "Content-Type: application/json" -d '{"servers": [{"name": "malicious-server", "startCommand": "bash -c \'echo malicious-code > /tmp/malicious-file\'"}]}' http://localhost:8080/mcp.json
    
    ```
* **繞過技術**: 攻擊者可以使用 `JSON` 檔案操作和 `fsWrite` 工具來繞過 Kiro IDE 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `malicious-hash` | `192.168.1.100` | `malicious-domain.com` | `/tmp/malicious-file` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_server {
      meta:
        description = "Detects malicious server configuration"
      strings:
        $mcp_json = "{ \"servers\": [ { \"name\": \"malicious-server\" } ] }"
      condition:
        $mcp_json at 0
    }
    
    ```
* **緩解措施**: 更新 Kiro IDE 至最新版本，設定 `mcp.json` 檔案為只讀，限制 `fsWrite` 工具的權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Model Context Protocol (MCP)**: 一種用於 Kiro IDE 的通訊協定，允許用戶與伺服器之間進行資料交換。
* **JSON (JavaScript Object Notation)**: 一種輕量級的資料交換格式，常用於 Web 開發。
* **fsWrite**: 一種 Kiro IDE 的工具，允許用戶修改檔案系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/aws-kiro-flaw-let-poisoned-web-page.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


