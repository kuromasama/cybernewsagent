---
layout: post
title:  "Agentjacking Attack Tricks AI Coding Agents Into Running Malicious Code"
date:   2026-06-12 14:42:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Agentjacking 攻擊：利用 Sentry 的設計缺陷進行任意代碼執行

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Sentry`, `MCP`, `Markdown Injection`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Sentry 的事件接收機制（Event Ingestion）允許任意 payload 的傳入，而 Sentry MCP 伺服器將這些事件作為可信任的系統輸出返回給 AI 代碼代理。這個設計缺陷使得攻擊者可以注入精心設計的錯誤報告，從而執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者找到目標的 Sentry Data Source Name (DSN)。
  2. 攻擊者使用 DSN 向 Sentry 的事件接收端點發送惡意錯誤事件。
  3. 惡意事件包含精心設計的 markdown 格式，當 Sentry MCP 伺服器返回這個事件給 AI 代碼代理時，會被渲染為與 Sentry 系統模板視覺上相同的結構化內容。
  4. 當開發者要求 AI 代碼代理「修復未解決的 Sentry 問題」時，代理會查詢 Sentry 並接收到惡意事件。
  5. 代理執行惡意代碼，該代碼以開發者的完整權限運行。
* **受影響元件**: Sentry 的所有版本，尤其是使用 MCP 的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 需要知道目標的 Sentry DSN。
* **Payload 建構邏輯**:

    ```
    
    python
      import requests
    
      # 定義 Sentry DSN 和惡意錯誤事件
      dsn = "https://examplePublicKey@o0.ingest.sentry.io/0"
      event = {
          "message": "Test Error",
          "context": {
              "key": "value"
          }
      }
    
      # 將惡意事件發送到 Sentry
      response = requests.post(dsn, json=event)
    
    ```
  *範例指令*: 使用 `curl` 發送惡意事件

```

bash
  curl -X POST \
  https://examplePublicKey@o0.ingest.sentry.io/0 \
  -H 'Content-Type: application/json' \
  -d '{"message": "Test Error", "context": {"key": "value"}}'

```
* **繞過技術**: 由於攻擊不涉及傳統的惡意代碼，因此可以繞過大多數的安全防護措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Sentry_Malicious_Event {
          meta:
              description = "Detects malicious Sentry events"
          strings:
              $s1 = "Test Error"
          condition:
              $s1
      }
    
    ```
  或者使用 SIEM 查詢語法進行偵測

```

sql
  SELECT * FROM sentry_events WHERE message LIKE '%Test Error%'

```
* **緩解措施**: 除了更新 Sentry 到最新版本外，還可以設定 Sentry 伺服器的內容過濾器，以阻止惡意事件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Sentry**: 一個開源的錯誤追蹤和性能監控平台。
* **MCP (Model Context Protocol)**: 一個用於 AI 代碼代理和 Sentry 伺服器之間通信的協議。
* **Markdown Injection**: 一種攻擊技術，通過注入精心設計的 markdown 格式來執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://thehackernews.com/2026/06/agentjacking-attack-tricks-ai-coding.html)
- [Sentry 官方文件](https://docs.sentry.io/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/)


