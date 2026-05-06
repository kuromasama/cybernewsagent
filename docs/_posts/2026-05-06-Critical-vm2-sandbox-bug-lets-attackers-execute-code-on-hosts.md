---
layout: post
title:  "Critical vm2 sandbox bug lets attackers execute code on hosts"
date:   2026-05-06 19:28:09 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Node.js vm2 Sandbox 逃逸漏洞：CVE-2026-26956
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: WebAssembly, JSTag, Sandbox Escape

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: vm2 沙盒庫在處理 WebAssembly 例外時，錯誤地允許攻擊者逃逸沙盒，執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者創建一個特殊的 TypeError，利用 Symbol-to-string 轉換。
  2. WebAssembly 例外處理攔截 JavaScript 錯誤，繞過 vm2 的 JavaScript 級別保護。
  3. 攻擊者利用 constructor chain，重新獲得 Node.js 內部對象的存取權。
  4. 攻擊者執行任意代碼，逃逸沙盒。
* **受影響元件**: vm2 3.10.4 版本，Node.js 25.6.1 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要 Node.js 25 版本，啟用 WebAssembly 例外處理和 JSTag 支持。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = {
      // 利用 Symbol-to-string 轉換創建 TypeError
      __proto__: {
        toString: () => {
          // 攻擊者代碼
          console.log('逃逸沙盒成功！');
        }
      }
    };
    
    ```
* **繞過技術**: 可以利用 WAF 的繞過技巧，例如使用 Base64 編碼或 URL 編碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule vm2_sandbox_escape {
      meta:
        description = "vm2 沙盒逃逸漏洞"
      strings:
        $payload = { 28 00 00 00 00 00 00 00 }
      condition:
        $payload at 0
    }
    
    ```
* **緩解措施**: 升級 vm2 至 3.10.5 版本或以上，禁用 WebAssembly 例外處理和 JSTag 支持。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebAssembly (WA)**: 一種新的二進制格式，允許在瀏覽器中執行原生代碼。
* **JSTag**: 一種 JavaScript 標籤，允許在 JavaScript 中使用原生代碼。
* **Sandbox Escape**: 一種攻擊技術，允許攻擊者逃逸沙盒，執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/critical-vm2-sandbox-bug-lets-attackers-execute-code-on-hosts/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


