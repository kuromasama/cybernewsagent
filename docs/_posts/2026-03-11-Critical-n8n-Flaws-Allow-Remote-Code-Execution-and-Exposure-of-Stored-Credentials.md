---
layout: post
title:  "Critical n8n Flaws Allow Remote Code Execution and Exposure of Stored Credentials"
date:   2026-03-11 18:45:03 +0000
categories: [security]
severity: critical
---

# 🚨 解析 n8n 工作流自動化平台的遠程命令執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.4-9.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Expression sandbox escape, Deserialization, Unauthenticated expression evaluation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: n8n 工作流自動化平台的表達式編譯器中存在一個缺陷，導致未經過適當的驗證和轉換的用戶輸入可以被執行，從而導致遠程命令執行。
* **攻擊流程圖解**: 
  1. 攻擊者提交一個精心設計的表達式到 n8n 平台。
  2. n8n 平台的表達式編譯器未能正確驗證和轉換該表達式。
  3. 該表達式被執行，導致遠程命令執行。
* **受影響元件**: n8n 版本 < 1.123.22, >= 2.0.0 < 2.9.3, 和 >= 2.10.0 < 2.10.1。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限創建或修改工作流。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      payload = {
        "name": "任意命令",
        "expression": "系統命令"
      }
    
    ```
  *範例指令*: 使用 `curl` 提交 Payload 到 n8n 平台。

```

bash
  curl -X POST \
  http://example.com/n8n/api/endpoint \
  -H 'Content-Type: application/json' \
  -d '{"name": "任意命令", "expression": "系統命令"}'

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全措施，例如使用 Base64 編碼或 URL 編碼來隱藏 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | XXXX | XXXX | XXXX |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule n8n_rce {
        meta:
          description = "n8n 遠程命令執行漏洞"
          author = "您的名字"
        strings:
          $payload = { 28 29 20 22 61 72 62 69 74 72 61 72 79 20 63 6f 6d 6d 61 6e 64 22 }
        condition:
          $payload at 0
      }
    
    ```
  或者是使用 Snort/Suricata Signature 來偵測：

```

snort
  alert tcp any any -> any any (msg:"n8n 遠程命令執行漏洞"; content:"|28 29 20 22 61 72 62 69 74 72 61 72 79 20 63 6f 6d 6d 61 6e 64 22|"; sid:1000000;)

```
* **緩解措施**: 除了更新修補之外，還可以限制工作流創建和編輯權限，部署 n8n 在一個加固的環境中，限制操作系統權限和網路存取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Expression sandbox escape**: 想像一個沙盒環境，攻擊者可以通過精心設計的表達式來逃離沙盒，執行任意命令。
  技術上是指攻擊者可以通過利用表達式編譯器的缺陷來執行任意命令。
* **Deserialization**: 想像一個序列化的數據，可以被反序列化為原始數據。
  技術上是指將序列化的數據轉換回原始數據的過程。
* **Unauthenticated expression evaluation**: 想像一個未經過驗證的用戶輸入，可以被執行為表達式。
  技術上是指未經過適當的驗證和轉換的用戶輸入可以被執行為表達式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/critical-n8n-flaws-allow-remote-code.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


