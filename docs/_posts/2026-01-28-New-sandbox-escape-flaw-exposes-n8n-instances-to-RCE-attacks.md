---
layout: post
title:  "New sandbox escape flaw exposes n8n instances to RCE attacks"
date:   2026-01-28 18:29:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 n8n 工作流自動化平台的兩個高風險漏洞：CVE-2026-1470 和 CVE-2026-0863

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.9)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: AST Sandbox Escape, JavaScript with Statement, Python AST Sandbox Escape, Format-String-Based Object Introspection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: CVE-2026-1470 是由於 n8n 工作流自動化平台的 JavaScript AST 沙盒逃逸漏洞，該漏洞是由於 `with` 陳述式的不當處理導致的。攻擊者可以利用這個漏洞在 n8n 的主節點上執行任意 JavaScript 代碼，從而實現 RCE。
* **攻擊流程圖解**:
  1. 攻擊者創建或修改一個工作流程，以便在 n8n 的主節點上執行任意 JavaScript 代碼。
  2. 攻擊者利用 `with` 陳述式的漏洞，逃逸 JavaScript 沙盒，獲得對主節點的控制權。
  3. 攻擊者在主節點上執行任意 JavaScript 代碼，實現 RCE。
* **受影響元件**: n8n 工作流自動化平台的版本 1.123.17 之前、2.4.5 之前和 2.5.1 之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要有創建或修改工作流程的權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = {
      "name": "example",
      "nodes": [
        {
          "parameters": {
            "function": "with ({}) { eval('console.log(\"Hello, World!\")') }"
          }
        }
      ]
    };
    
    ```
* **範例指令**: 使用 `curl` 工具發送 HTTP 請求，創建或修改工作流程。

```

bash
curl -X POST \
  http://example.com/api/workflows \
  -H 'Content-Type: application/json' \
  -d '{"name": "example", "nodes": [{"parameters": {"function": "with ({}) { eval(\'console.log(\"Hello, World!\")\') }"}}]}'

```
* **繞過技術**: 攻擊者可以利用 WAF 或 EDR 繞過技巧，例如使用 Base64 編碼或其他編碼方式來隱藏 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /api/workflows |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule n8n_rce {
      meta:
        description = "Detects n8n RCE vulnerability"
        author = "Your Name"
      strings:
        $payload = "with ({}) { eval('"
      condition:
        $payload in (http.request_body | strings)
    }
    
    ```
* **緩解措施**: 更新 n8n 工作流自動化平台到最新版本，例如 1.123.17、2.4.5 或 2.5.1。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **AST (Abstract Syntax Tree)**: 一種樹狀結構，代表了源代碼的抽象語法結構。
* **Sandbox**: 一種安全機制，限制了代碼的執行環境和權限。
* **RCE (Remote Code Execution)**: 一種攻擊方式，允許攻擊者在遠程主機上執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.bleepingcomputer.com/news/security/new-sandbox-escape-flaw-exposes-n8n-instances-to-rce-attacks/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


