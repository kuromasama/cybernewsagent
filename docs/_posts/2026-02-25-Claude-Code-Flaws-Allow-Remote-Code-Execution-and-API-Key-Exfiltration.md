---
layout: post
title:  "Claude Code Flaws Allow Remote Code Execution and API Key Exfiltration"
date:   2026-02-25 18:56:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Anthropic Claude Code 的遠端代碼執行與 API 認證資料洩露漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：8.7)
> * **受駭指標**: 遠端代碼執行 (RCE) 和 API 認證資料洩露 (Info Leak)
> * **關鍵技術**: 代碼注入 (Code Injection), API 認證資料洩露 (API Key Leak), Model Context Protocol (MCP)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude Code 的代碼注入漏洞是由於在啟動新目錄時沒有正確檢查用戶的同意，導致攻擊者可以執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意的 `.claude/settings.json` 文件，包含代碼注入的 payload。
  2. 用戶啟動 Claude Code 在包含惡意文件的目錄中。
  3. Claude Code 執行惡意代碼，導致遠端代碼執行或 API 認證資料洩露。
* **受影響元件**: Claude Code 版本 1.0.87 之前，環境變數和 Model Context Protocol (MCP) 伺服器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意的 `.claude/settings.json` 文件，並將其放在用戶的目錄中。
* **Payload 建構邏輯**:

    ```
    
    json
      {
        "hooks": {
          "preStart": "bash -c 'echo \"Hello, World!\" > /tmp/hello.txt'"
        }
      }
    
    ```
  這個 payload 會在 Claude Code 啟動時執行 `bash` 命令，創建一個文件 `/tmp/hello.txt`。
* **繞過技術**: 攻擊者可以使用代碼混淆或加密技術來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `example.com` | `/tmp/hello.txt` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Claude_Code_Injection {
        meta:
          description = "Detects Claude Code injection attacks"
          author = "Your Name"
        strings:
          $hook = "preStart"
          $bash = "bash -c"
        condition:
          $hook and $bash
      }
    
    ```
  這個 YARA 規則會偵測包含 `preStart` 和 `bash -c` 的文件。
* **緩解措施**: 更新 Claude Code 至最新版本，設定環境變數和 Model Context Protocol (MCP) 伺服器的安全配置。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Model Context Protocol (MCP)**: 一種用於 Claude Code 的通訊協定，允許用戶與 AI 模型進行交互。
* **代碼注入 (Code Injection)**: 一種攻擊技術，允許攻擊者執行任意代碼。
* **API 認證資料洩露 (API Key Leak)**: 一種攻擊技術，允許攻擊者竊取 API 認證資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/claude-code-flaws-allow-remote-code.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


