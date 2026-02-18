---
layout: post
title:  "Microsoft: Anti-phishing rules mistakenly blocked emails, Teams messages"
date:   2026-02-18 18:44:11 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Exchange Online 錯誤隔離合法郵件事件
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: False Positive (誤判合法郵件為惡意)
> * **關鍵技術**: Heuristic Detection, Credential Phishing, Email Security

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft 的 email 安全系統中有一個邏輯錯誤，導致合法的 URL 被誤判為惡意連結。這個錯誤發生在一個名為「heuristic detection」的系統中，該系統設計用來偵測新型的 credential phishing 攻擊。
* **攻擊流程圖解**: 
  1. Microsoft 更新了 heuristic detection 系統。
  2. 系統開始誤判合法 URL 為惡意連結。
  3. 自動化反應機制被觸發，導致郵件被隔離。
* **受影響元件**: Microsoft Exchange Online 和 Microsoft Teams。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要了解 Microsoft 的 email 安全系統和 heuristic detection 機制。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    url = "https://example.com/legitimate-url"
    payload = {
        "url": url,
        "subject": "Legitimate Email",
        "body": "This is a legitimate email."
    }
    
    ```
    *範例指令*: 使用 `curl` 發送郵件

```

bash
curl -X POST \
  https://example.com/send-email \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://example.com/legitimate-url", "subject": "Legitimate Email", "body": "This is a legitimate email."}'

```
* **繞過技術**: 攻擊者可以嘗試使用不同的 URL 或郵件內容來繞過 heuristic detection 機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Exchange_False_Positive {
      meta:
        description = "Detect Microsoft Exchange false positive"
      strings:
        $url = "https://example.com/legitimate-url"
      condition:
        $url
    }
    
    ```
    或者是使用 Splunk 查詢語法

```

spl
index=mail sourcetype="microsoft_exchange" url="https://example.com/legitimate-url"

```
* **緩解措施**: 更新 Microsoft Exchange 系統和 heuristic detection 機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heuristic Detection (啟發式偵測)**: 一種使用機器學習和統計方法來偵測未知威脅的技術。
* **Credential Phishing (憑證釣魚)**: 一種攻擊者嘗試竊取使用者憑證的攻擊。
* **Email Security (郵件安全)**: 一種保護郵件系統和使用者免受攻擊的技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-anti-phishing-rules-mistakenly-blocked-emails-teams-messages/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


