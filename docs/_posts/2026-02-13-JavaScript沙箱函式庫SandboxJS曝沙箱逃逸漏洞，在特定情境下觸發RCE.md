---
layout: post
title:  "JavaScript沙箱函式庫SandboxJS曝沙箱逃逸漏洞，在特定情境下觸發RCE"
date:   2026-02-13 06:52:32 +0000
categories: [security]
severity: critical
---

# 🚨 SandboxJS 沙箱逃逸漏洞解析：CVE-2026-25881
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS v3.1 分數為 9.1)
> * **受駭指標**: RCE (遠端程式碼執行)
> * **關鍵技術**: Prototype Pollution, Sandbox Escape, JavaScript

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SandboxJS 使用一個名為 `isGlobal` 的保護旗標，試圖阻止沙箱內程式碼改寫全域物件或其原型。然而，在陣列常值或物件常值的建立過程中，該保護旗標可能在轉換流程中遺失，導致原本應被阻擋的原型寫入不再被攔截。
* **攻擊流程圖解**: 
  1. 攻擊者在沙箱內執行不受信任的程式碼。
  2. 程式碼嘗試改寫宿主的內建原型（例如 `Map.prototype` 或 `Set.prototype`）。
  3. 由於 `isGlobal` 旗標的遺失，沙箱邊界被繞過，原型寫入成功。
  4. 攻擊者可以利用污染的原型，進一步實現 RCE。
* **受影響元件**: SandboxJS 版本早於 0.8.31。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在沙箱內執行不受信任的程式碼。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 範例 Payload
      const payload = {
        __proto__: Map.prototype,
        foo: 'bar'
      };
    
    ```
  *範例指令*:

```

bash
  curl -X POST \
  http://example.com/sandbox \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"foo": "bar"}}'

```
* **繞過技術**: 攻擊者可以利用 SandboxJS 的漏洞，繞過沙箱邊界，實現 RCE。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /sandbox |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule SandboxJS_Vulnerability {
        meta:
          description = "SandboxJS Vulnerability Detection"
          author = "Your Name"
        strings:
          $payload = "__proto__"
        condition:
          $payload
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
  index=sandboxjs | search "__proto__"

```
* **緩解措施**: 
  1. 升級 SandboxJS 至 0.8.31 或更新版本。
  2. 在宿主程序執行不受信任程式碼之前，先凍結內建原型，降低被改寫的風險。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Prototype Pollution**: 想像兩個物件同時繼承同一個原型。技術上是指攻擊者可以污染 JavaScript 的原型鏈，進一步實現 RCE。
* **Sandbox Escape**: 攻擊者可以繞過沙箱邊界，實現 RCE。
* **JavaScript**: 一種高級的、動態的、基於原型的語言。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173940)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


