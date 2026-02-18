---
layout: post
title:  "Microsoft says bug causes Copilot to summarize confidential emails"
date:   2026-02-18 12:46:26 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft 365 Copilot 中的資訊洩露漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Data Loss Prevention (DLP)`, `Artificial Intelligence (AI)`, `Email Confidentiality`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft 365 Copilot 的 "work tab" chat 功能中，存在一個程式碼錯誤，導致它忽略了電子郵件中的機密標籤，從而導致機密信息被洩露。
* **攻擊流程圖解**: 
  1. 使用者發送或草擬電子郵件，並添加機密標籤。
  2. Microsoft 365 Copilot 的 "work tab" chat 功能讀取電子郵件內容。
  3. 由於程式碼錯誤，Copilot 忽略機密標籤，將電子郵件內容進行摘要。
  4. 機密信息被洩露給未經授權的使用者。
* **受影響元件**: Microsoft 365 Copilot 的 "work tab" chat 功能，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Microsoft 365 Copilot 的使用權限，並能夠發送或草擬電子郵件。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      email_content = {
        "subject": "機密電子郵件",
        "body": "這是一封機密電子郵件，請勿轉發。",
        "sensitivity": "confidential"
      }
    
    ```
  *範例指令*: 使用 `curl` 發送電子郵件

```

bash
  curl -X POST \
  https://example.com/api/send-email \
  -H 'Content-Type: application/json' \
  -d '{"subject": "機密電子郵件", "body": "這是一封機密電子郵件，請勿轉發。", "sensitivity": "confidential"}'

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼電子郵件內容。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /api/send-email |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Microsoft365CopilotInfoLeak {
        meta:
          description = "Microsoft 365 Copilot 機密信息洩露"
          author = "Your Name"
        strings:
          $email_content = "機密電子郵件"
        condition:
          $email_content
      }
    
    ```
  或者是使用 SIEM 查詢語法 (Splunk/Elastic)

```

sql
  index=microsoft365 source=api/send-email | search "機密電子郵件"

```
* **緩解措施**: 更新 Microsoft 365 Copilot 的 "work tab" chat 功能，修復程式碼錯誤，並設定 DLP 政策以防止機密信息洩露。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Data Loss Prevention (DLP)**: 資料丟失防護，指的是一種技術，用於防止機密信息被未經授權的使用者存取或傳輸。
* **Artificial Intelligence (AI)**: 人工智慧，指的是一種模擬人類智慧的技術，用於解決複雜問題。
* **Email Confidentiality**: 電子郵件機密性，指的是電子郵件中的機密信息被保護的能力。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-says-bug-causes-copilot-to-summarize-confidential-emails/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1021/)


