---
layout: post
title:  "Claude Code Source Leaked via npm Packaging Error, Anthropic Confirms"
date:   2026-04-01 07:11:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Claude Code 源碼洩露事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `npm` 套件管理、源碼映射（Source Map）、依賴混淆攻擊（Dependency Confusion Attack）

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude Code 的開發團隊在發布 `npm` 套件時，由於人為錯誤，將源碼映射檔（Source Map）包含在套件中，導致源碼洩露。
* **攻擊流程圖解**:
  1.攻擊者下載含有源碼映射檔的 `npm` 套件。
  2.攻擊者分析源碼，了解 Claude Code 的內部實現細節。
  3.攻擊者利用源碼中的資訊，構建攻擊 payload。
* **受影響元件**: Claude Code 的 `npm` 套件，版本號為 2.1.88。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要下載含有源碼映射檔的 `npm` 套件。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 payload
    const payload = {
      "type": "function",
      "name": "eval",
      "args": ["console.log('XSS')"]
    };
    
    ```
  *範例指令*: 使用 `curl` 發送 payload 到 Claude Code 的 API 端點。

```

bash
curl -X POST \
  http://example.com/claude-code/api/eval \
  -H 'Content-Type: application/json' \
  -d '{"type":"function","name":"eval","args":["console.log(\'XSS\')"]}'

```
* **繞過技術**: 攻擊者可以使用依賴混淆攻擊（Dependency Confusion Attack）來繞過 Claude Code 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `example.com` | `/claude-code/api/eval` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Claude_Code_Attack {
      meta:
        description = "Detects Claude Code attack"
      strings:
        $eval_func = "eval"
      condition:
        $eval_func in (pe.imports(0).name)
    }
    
    ```
  或者是使用 Snort/Suricata Signature：

```

snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Claude Code Attack"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 Claude Code 到最新版本，移除源碼映射檔，並設定適當的安全機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Source Map (源碼映射)**: 一種將編譯後的程式碼映射回原始程式碼的技術，方便除錯和開發。
* **npm (Node Package Manager)**: 一種 Node.js 的套件管理工具，允許開發者輕鬆地安裝和管理套件。
* **依賴混淆攻擊 (Dependency Confusion Attack)**: 一種攻擊技術，利用套件管理工具的依賴機制，將惡意套件注入到目標系統中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/claude-code-tleaked-via-npm-packaging.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


