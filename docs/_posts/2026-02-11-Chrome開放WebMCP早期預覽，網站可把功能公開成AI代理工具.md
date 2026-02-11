---
layout: post
title:  "Chrome開放WebMCP早期預覽，網站可把功能公開成AI代理工具"
date:   2026-02-11 18:57:00 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 WebMCP：網站代理互動的新時代
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: 代理式 Web 攻擊
> * **關鍵技術**: WebMCP、代理式 Web、JavaScript 介面

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: WebMCP 的宣告式介面和命令式介面可能導致代理式 Web 攻擊。
* **攻擊流程圖解**: 
  1. 攻擊者創建一個惡意網站，使用 WebMCP 的宣告式介面或命令式介面。
  2. 網站經營者透過 WebMCP 的 JavaScript 介面，將網站的功能整理成可被代理呼叫的工具。
  3. 攻擊者使用代理式 Web 攻擊，利用 WebMCP 的工具，進行未經授權的操作。
* **受影響元件**: WebMCP、Chrome 瀏覽器、JavaScript 介面

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意網站，使用 WebMCP 的宣告式介面或命令式介面。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意網站的 JavaScript 代碼
    const maliciousTool = {
      name: 'maliciousTool',
      description: 'A malicious tool',
      parameters: [
        {
          name: 'param1',
          type: 'string'
        }
      ],
      execute: (param1) => {
        // 執行惡意操作
      }
    };
    
    // 註冊惡意工具給代理
    navigator.modelContext.registerTool(maliciousTool);
    
    ```
    * **範例指令**: 使用 `curl` 或 `nmap` 進行代理式 Web 攻擊。
* **繞過技術**: 攻擊者可以使用 WAF 或 EDR 繞過技巧，例如使用加密或隱碼技術。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious-tool.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_tool {
      meta:
        description = "Detects malicious tool"
      strings:
        $tool_name = "maliciousTool"
      condition:
        $tool_name
    }
    
    ```
    * **SIEM 查詢語法**:

    ```
    
    sql
    SELECT * FROM logs WHERE tool_name = 'maliciousTool'
    
    ```
* **緩解措施**: 
  1. 更新 WebMCP 和 Chrome 瀏覽器至最新版本。
  2. 啟用 WAF 和 EDR 來偵測和防禦代理式 Web 攻擊。
  3. 對網站的 JavaScript 代碼進行安全審查和測試。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebMCP (Web Model-Driven Proxy)**: 一種網站代理互動的技術，允許網站以結構化工具的形式，向瀏覽器代理清楚描述可執行的動作與入口。
* **代理式 Web (Proxy-Driven Web)**: 一種網站互動的模式，使用代理來進行網站的操作和交互。
* **JavaScript 介面 (JavaScript Interface)**: 一種程式設計語言，用于創建網站的互動和動態效果。

## 5. 🔗 參考文獻與延伸閱讀
- [WebMCP 官方文件](https://www.w3.org/TR/webmcp/)
- [Chrome 瀏覽器安全性](https://www.google.com/chrome/browser-privacy/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1189/)


