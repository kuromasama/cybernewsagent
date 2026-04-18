---
layout: post
title:  "Critical flaw in Protobuf library enables JavaScript code execution"
date:   2026-04-18 18:37:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Protobuf.js 遠程代碼執行漏洞：利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `protobuf.js`, `JavaScript`, `Deserialization`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Protobuf.js 中的 `Function()` 建構函數未能正確驗證來自 protobuf 結構的識別符，導致攻擊者可以注入任意代碼。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個惡意的 protobuf 結構。
    2. 攻擊者將惡意結構發送給受影響的應用程序。
    3. 受影響的應用程序使用 `Function()` 建構函數來執行 protobuf 結構。
    4. 攻擊者注入的代碼被執行，導致遠程代碼執行。
* **受影響元件**: Protobuf.js 版本 8.0.0/7.5.4 及更低版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道受影響的應用程序使用的 protobuf 結構。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例惡意 protobuf 結構
    const maliciousSchema = {
      type: 'object',
      properties: {
        foo: {
          type: 'string',
          default: 'alert("XSS")'
        }
      }
    };
    
    ```
    * 攻擊者可以使用 `curl` 或其他工具將惡意結構發送給受影響的應用程序。

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"foo": "alert(\"XSS\")"}' http://example.com/api

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦措施，例如使用 Base64 編碼或其他編碼方式來隱藏惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule protobuf_rce {
      meta:
        description = "Detects malicious protobuf structures"
      strings:
        $s1 = "Function(" ascii
      condition:
        $s1
    }
    
    ```
    * SIEM 查詢語法 (Splunk/Elastic):

    ```
    
    sql
    index=main sourcetype=protobuf | search "Function(" | stats count as num_events
    
    ```
* **緩解措施**: 更新 Protobuf.js 至 8.0.1 或 7.5.5 版本，並在應用程序中實施輸入驗證和編碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **protobuf**: 一種由 Google 開發的序列化格式，用于存儲和交換結構化數據。
* **Deserialization**: 將序列化的數據轉換回原始數據結構的過程。
* **Function() 建構函數**: 一種 JavaScript 函數，用于創建新的函數。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/critical-flaw-in-protobuf-library-enables-javascript-code-execution/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


