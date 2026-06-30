---
layout: post
title:  "Progress Kemp LoadMaster Flaw Could Let Attackers Run Root Commands Pre-Auth"
date:   2026-06-30 09:21:58 +0000
categories: [security]
severity: critical
---

# 🚨 進階漏洞利用：解析 Progress Kemp LoadMaster 命令執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Command Execution)
> * **關鍵技術**: `Heap Spraying`, `JSON Injection`, `Command Injection`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 這個漏洞的根源在於 `escape_quotes()` 函數中，沒有正確地初始化記憶體緩衝區，並且沒有在 sanitizedName 字串的末尾添加 null 終止符。這導致了當系統嘗試存取 sanitizedName 時，會超出緩衝區的範圍，從而讀取到鄰近的記憶體位置。
* **攻擊流程圖解**:
  1. 攻擊者發送一個精心構造的 JSON 請求到 `/accessv2` 端點。
  2. 請求中包含一個 `apiuser` 欄位和多個額外的 key-value 對，目的是注入命令。
  3. `escape_quotes()` 函數嘗試對 `apiuser` 欄位進行 sanitization，但由於沒有正確初始化記憶體緩衝區和添加 null 終止符，導致系統讀取到鄰近的記憶體位置。
  4. 系統執行注入的命令，作為 root 用戶。
* **受影響元件**: LoadMaster GA v7.2.63.1 和舊版本，LoadMaster LTSF v7.2.54.17 和舊版本，當 API 啟用時。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 無需有效憑證，僅需能夠發送請求到 `/accessv2` 端點。
* **Payload 建構邏輯**:

    ```
    
    json
      {
        "apiuser": "crafted_apiuser",
        "key1": "command1",
        "key2": "command2",
        ...
      }
    
    ```
 

```

bash
  curl -X POST \
  http://example.com/accessv2 \
  -H 'Content-Type: application/json' \
  -d '{"apiuser": "crafted_apiuser", "key1": "command1", "key2": "command2"}'

```
* **繞過技術**: 目前沒有相關的 WAF 或 EDR 繞過技巧被公開。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule LoadMaster_Command_Injection {
        meta:
          description = "Detects potential command injection in LoadMaster"
          author = "Your Name"
        strings:
          $json_payload = "{ \"apiuser\": \"*\", \"key*\": \"*\" }"
        condition:
          $json_payload
      }
    
    ```
 

```

snort
  alert tcp any any -> any 80 (msg:"LoadMaster Command Injection"; content:"|7b 20 22 61 70 69 75 73 65 72 22 3a 20 22|"; sid:1000001;)

```
* **緩解措施**: 更新 LoadMaster 至最新版本 (GA v7.2.63.2 或 LTSF v7.2.54.18)，並考慮限制 API 的存取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 一種攻擊技術，通過在堆上分配大量的記憶體，嘗試覆蓋特定的記憶體位置，以便注入惡意代碼。
* **JSON Injection**: 一種攻擊技術，通過注入精心構造的 JSON 數據，嘗試操控應用程序的行為。
* **Command Injection**: 一種攻擊技術，通過注入系統命令，嘗試執行任意命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/progress-kemp-loadmaster-flaw-could-let.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


