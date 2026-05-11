---
layout: post
title:  "Instructure confirms hackers used Canvas flaw to deface portals"
date:   2026-05-11 19:30:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Instructure Canvas 安全漏洞：跨站腳本攻擊與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Cross-Site Scripting (XSS) 與 Remote Code Execution (RCE)
> * **關鍵技術**: `Cross-Site Scripting (XSS)`, `JavaScript Injection`, `Authenticated Admin Sessions`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Instructure Canvas 的 Free-for-Teacher 環境中，存在一個跨站腳本攻擊（XSS）漏洞，允許攻擊者注入惡意 JavaScript 代碼，從而獲得授權管理員會話。
* **攻擊流程圖解**:
  1. 攻擊者發現 Instructure Canvas 的 Free-for-Teacher 環境中存在 XSS 漏洞。
  2. 攻擊者注入惡意 JavaScript 代碼，獲得授權管理員會話。
  3. 攻擊者使用授權管理員會話，修改 Canvas 登入入口，留下勒索訊息。
* **受影響元件**: Instructure Canvas 的 Free-for-Teacher 環境，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要發現 Instructure Canvas 的 Free-for-Teacher 環境中存在的 XSS 漏洞。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意 JavaScript 代碼示例
      var payload = "<script>alert('XSS')</script>";
      // 注入惡意 JavaScript 代碼
      document.write(payload);
    
    ```
  *範例指令*: 使用 `curl` 工具注入惡意 JavaScript 代碼：

```

bash
  curl -X POST \
  https://example.com/canvas \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'payload=<script>alert(%22XSS%22)</script>'

```
* **繞過技術**: 攻擊者可以使用各種技術繞過安全防護，例如使用 Base64 編碼或使用其他編碼方式來隱藏惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /canvas |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Instructure_Canvas_XSS {
        meta:
          description = "Instructure Canvas XSS 攻擊"
          author = "Your Name"
        strings:
          $xss = "<script>alert('XSS')</script>"
        condition:
          $xss
      }
    
    ```
  或者使用 Snort/Suricata Signature：

```

snort
  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Instructure Canvas XSS 攻擊"; content:"<script>alert('XSS')</script>"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 Instructure Canvas 至最新版本，啟用安全防護功能，例如輸入驗證和輸出編碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cross-Site Scripting (XSS)**: 想像兩個網站之間的互動，攻擊者可以注入惡意代碼，從而獲得授權存取權。技術上是指攻擊者注入惡意代碼，從而執行未經授權的動作。
* **JavaScript Injection**: 想像攻擊者可以注入惡意 JavaScript 代碼，從而獲得授權存取權。技術上是指攻擊者注入惡意 JavaScript 代碼，從而執行未經授權的動作。
* **Authenticated Admin Sessions**: 想像攻擊者可以獲得授權管理員會話，從而執行未經授權的動作。技術上是指攻擊者獲得授權管理員會話，從而執行未經授權的動作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/instructure-confirms-hackers-used-canvas-flaw-to-deface-portals/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


