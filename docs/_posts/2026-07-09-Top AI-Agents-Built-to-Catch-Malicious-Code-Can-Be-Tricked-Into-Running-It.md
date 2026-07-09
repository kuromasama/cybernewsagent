---
layout: post
title:  "Top AI Agents Built to Catch Malicious Code Can Be Tricked Into Running It"
date:   2026-07-09 09:26:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 AI 代碼代理的安全漏洞：Friendly Fire 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程代碼執行 (RCE)
> * **關鍵技術**: 自動化代碼審查、命令執行、社交工程

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: AI 代碼代理的自動化代碼審查功能中，存在一個安全漏洞，允許攻擊者通過提交特製的代碼，執行任意命令。
* **攻擊流程圖解**:
  1. 攻擊者提交一個包含惡意代碼的 pull request。
  2. AI 代碼代理自動審查代碼，執行安全檢查。
  3. 攻擊者在代碼中加入了一個隱藏的命令，該命令會在 AI 代碼代理執行安全檢查時被執行。
  4. AI 代碼代理執行該命令，導致遠程代碼執行。
* **受影響元件**: Claude Code、OpenAI Codex 等 AI 代碼代理。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要提交一個包含惡意代碼的 pull request。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意代碼示例
      import os
      os.system("echo 'Hello, World!' > /tmp/hello.txt")
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"code": "import os; os.system(\"echo \'Hello, World!\' > /tmp/hello.txt\")"}' http://example.com/api/audit`
* **繞過技術**: 攻擊者可以使用社交工程技術，讓 AI 代碼代理執行惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/hello.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_code {
        meta:
          description = "Detects malicious code"
        strings:
          $a = "os.system"
        condition:
          $a
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
  index=security sourcetype=api_audit code="*os.system*"

```
* **緩解措施**: 除了更新修補之外，還可以設定 AI 代碼代理的安全檢查功能，僅允許執行特定的命令。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AI 代碼代理 (AI Code Agent)**: 一種自動化代碼審查工具，使用 AI 技術來檢查代碼的安全性和質量。
* **自動化代碼審查 (Automated Code Review)**: 一種使用工具來自動化代碼審查的過程，目的是提高代碼的質量和安全性。
* **遠程代碼執行 (Remote Code Execution)**: 一種攻擊技術，允許攻擊者在遠程主機上執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/friendly-fire-ai-agents-built-to-catch.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


