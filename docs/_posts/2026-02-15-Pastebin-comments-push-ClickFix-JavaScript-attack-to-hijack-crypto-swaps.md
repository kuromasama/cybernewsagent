---
layout: post
title:  "Pastebin comments push ClickFix JavaScript attack to hijack crypto swaps"
date:   2026-02-15 18:27:09 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Pastebin 評論中的 ClickFix 式攻擊：利用 JavaScript 劫持比特幣交易

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `JavaScript Injection`, `ClickFix`, `Social Engineering`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Pastebin 評論發佈假的加密貨幣漏洞，誘騙用戶執行惡意 JavaScript 代碼，從而劫持比特幣交易。
* **攻擊流程圖解**:
  1. 攻擊者發佈假的加密貨幣漏洞評論，包含惡意 JavaScript 代碼連結。
  2. 用戶點擊連結，訪問 Google Docs 頁面，包含假的漏洞文件。
  3. 用戶按照文件指示，執行惡意 JavaScript 代碼，劫持比特幣交易。
* **受影響元件**: Swapzone.io、ChangeNOW、比特幣交易所

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶必須訪問 Swapzone.io，且具有比特幣交易權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 代碼
    const maliciousCode = `
      // 劫持比特幣交易
      const bitcoinTransaction = {
        // ...
      };
      // ...
    `;
    // 執行惡意代碼
    eval(maliciousCode);
    
    ```
*範例指令*:

```

bash
curl -X POST \
  https://swapzone.io/api/transactions \
  -H 'Content-Type: application/json' \
  -d '{"transaction": {"..."}}'

```
* **繞過技術**: 攻擊者可以使用社交工程術，誘騙用戶執行惡意代碼，從而繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_javascript {
      meta:
        description = "惡意 JavaScript 代碼"
      strings:
        $a = "eval(" // 執行惡意代碼
      condition:
        $a
    }
    
    ```
* **緩解措施**: 用戶應避免執行來自未知來源的 JavaScript 代碼，且應啟用瀏覽器的安全防護功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix**: 一種社交工程術，誘騙用戶執行惡意代碼。
* **JavaScript Injection**: 一種攻擊技術，將惡意 JavaScript 代碼注入網頁中。
* **Social Engineering**: 一種攻擊技術，利用心理操縱誘騙用戶執行惡意行為。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/pastebin-comments-push-clickfix-javascript-attack-to-hijack-crypto-swaps/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


