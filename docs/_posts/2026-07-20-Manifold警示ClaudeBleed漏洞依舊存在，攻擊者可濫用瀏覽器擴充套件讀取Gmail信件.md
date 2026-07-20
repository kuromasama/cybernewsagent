---
layout: post
title:  "Manifold警示ClaudeBleed漏洞依舊存在，攻擊者可濫用瀏覽器擴充套件讀取Gmail信件"
date:   2026-07-20 13:53:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ClaudeBleed 漏洞：利用未經驗證的點擊事件執行任意指令
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `event.isTrusted`, `DOM Injection`, `JavaScript Injection`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude for Chrome 擴充套件未正確驗證觸發 AI 自動執行任務的點擊事件屬性 (`event.isTrusted`), 導致攻擊者可以透過網頁指令碼注入偽造的點擊事件。
* **攻擊流程圖解**: 
  1. 攻擊者創建一個惡意網頁，包含偽造的點擊事件。
  2. 用戶訪問惡意網頁，觸發偽造的點擊事件。
  3. Claude for Chrome 擴充套件接收到偽造的點擊事件，未進行驗證。
  4. Claude for Chrome 執行預設的 9 項固定任務，包括讀取 Gmail、Google 文件和行事曆等。
* **受影響元件**: Claude for Chrome 擴充套件，版本 1.0.80 或之前。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意網頁，包含偽造的點擊事件。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const payload = {
      "type": "click",
      "target": "claude.ai",
      "data": {
        "action": "readGmail"
      }
    };
    
    // 使用 JavaScript 注入偽造的點擊事件
    const event = new MouseEvent("click", {
      bubbles: true,
      cancelable: true,
      view: window
    });
    event.isTrusted = true; // 設定 event.isTrusted 屬性為 true
    document.dispatchEvent(event);
    
    ```
* **繞過技術**: 攻擊者可以使用 DOM Injection 和 JavaScript Injection 技術來繞過 Claude for Chrome 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ClaudeBleed_Detection {
      meta:
        description = "Detect ClaudeBleed exploit"
      strings:
        $s1 = "claude.ai"
        $s2 = "event.isTrusted"
      condition:
        all of them
    }
    
    ```
* **緩解措施**: 關閉 Claude for Chrome 的「無需詢問即可執行」的模式，限制 AI 代理須經用戶核准才能執行任務。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **event.isTrusted**: 一個布林值，表示事件是否來自真實的使用者。
* **DOM Injection**: 一種攻擊技術，通過注入惡意的 DOM 元素來實現攻擊。
* **JavaScript Injection**: 一種攻擊技術，通過注入惡意的 JavaScript 代碼來實現攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177461)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


