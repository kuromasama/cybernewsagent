---
layout: post
title:  "n8n Sandbox Escape Lets Workflow Editors Run OS Commands as the n8n Process"
date:   2026-07-27 14:15:11 +0000
categories: [security]
severity: high
---

# 🔥 解析 n8n 高風險表達式沙盒逃逸漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 4.0 分數：8.7)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `JavaScript`, `Node.js`, `Sandbox Escape`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: n8n 的表達式沙盒機制中，存在兩個漏洞：一是 `VariablePolyfill.ts` 中的 `ArrowFunctionExpression` 處理不當，允許攻擊者使用 `process` 物件；二是 `Reflect.get()` 方法中的屬性檢查不夠嚴格，允許攻擊者存取 `process.getBuiltinModule` 和 `child_process`。
* **攻擊流程圖解**:
  1. 攻擊者創建或修改工作流程，注入惡意表達式。
  2. n8n 的沙盒機制嘗試重寫表達式中的自由 JavaScript 識別符，但由於漏洞，攻擊者可以繞過這個機制。
  3. 攻擊者使用 `Reflect.get()` 方法存取 `process.getBuiltinModule` 和 `child_process`，從而執行任意系統命令。
* **受影響元件**: n8n 版本 <2.31.5 和 >=2.32.0,<2.32.1。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個有效的 n8n 帳戶，並具有創建或修改工作流程的權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = {
      "expression": "={{ $json.email }}",
      "function": "() => process"
    };
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      http://example.com/n8n/api/workflows \
      -H 'Content-Type: application/json' \
      -d '{"expression": "={{ $json.email }}", "function": "() => process"}'
    
    ```
* **繞過技術**: 攻擊者可以使用 `Reflect.get()` 方法繞過 n8n 的屬性檢查機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule n8n_sandbox_escape {
      meta:
        description = "n8n 沙盒逃逸漏洞"
      strings:
        $a = "process"
        $b = "child_process"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新 n8n 至版本 2.31.5 或 2.32.1，限制工作流程編輯權限，並監控系統命令執行情況。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Sandbox Escape**: 沙盒逃逸是一種攻擊技術，允許攻擊者繞過沙盒機制，執行任意系統命令。
* **Reflect.get()**: `Reflect.get()` 是一個 JavaScript 方法，允許攻擊者存取物件的屬性。
* **ArrowFunctionExpression**: `ArrowFunctionExpression` 是一種 JavaScript 語法，允許攻擊者定義箭頭函數。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/n8n-sandbox-escape-lets-workflow.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


