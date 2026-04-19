---
layout: post
title:  "Apple account change alerts abused to send phishing emails"
date:   2026-04-19 18:39:12 +0000
categories: [security]
severity: high
---

# 🔥 解析 Apple 帳戶變更通知被利用的技術細節
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Phishing, Social Engineering
> * **關鍵技術**: Apple 帳戶變更通知, Phishing, Social Engineering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Apple 帳戶變更通知的機制允許攻擊者在使用者個人資料欄位中插入惡意內容，從而發送假的 iPhone 購買詐騙郵件。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個 Apple ID 並在個人資料欄位中插入惡意內容。
    2. 攻擊者修改帳戶的運送信息，觸發 Apple 的安全提醒通知。
    3. Apple 的安全提醒通知包含使用者提供的第一和最後名稱欄位，從而將惡意內容嵌入郵件中。
* **受影響元件**: Apple 帳戶變更通知機制，所有使用 Apple 帳戶的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個 Apple ID 並在個人資料欄位中插入惡意內容。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    payload = {
        "first_name": "Dear User 899 USD iPhone Purchase Via Pay-Pal To Cancel",
        "last_name": "18023530761"
    }
    
    ```
    * **範例指令**: 攻擊者可以使用以下指令來發送惡意郵件：

```

bash
curl -X POST \
  https://www.apple.com/account \
  -H 'Content-Type: application/json' \
  -d '{"first_name": "Dear User 899 USD iPhone Purchase Via Pay-Pal To Cancel", "last_name": "18023530761"}'

```
* **繞過技術**: 攻擊者可以使用社交工程技術來繞過用戶的警惕，例如使用假的 Apple 支援電話號碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 值 |
| --- | --- |
| IP | 17.111.110.47 |
| Domain | apple.com |
| File Path | /account |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Apple_Phishing_Email {
        meta:
            description = "Apple 帳戶變更通知被利用的惡意郵件"
            author = "Your Name"
        strings:
            $a = "Dear User 899 USD iPhone Purchase Via Pay-Pal To Cancel"
            $b = "18023530761"
        condition:
            $a and $b
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=mail_logs (subject="Apple 帳戶變更通知" AND body="Dear User 899 USD iPhone Purchase Via Pay-Pal To Cancel" AND body="18023530761")
    
    ```
* **緩解措施**: 用戶應該對於來自 Apple 的郵件保持警惕，特別是那些要求用戶呼叫支援電話號碼的郵件。用戶應該直接聯繫 Apple 的官方支援電話號碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing (網釣)**: 想像一個釣魚者在網路上釣取用戶的敏感信息。技術上是指攻擊者使用假的郵件或網站來欺騙用戶提供敏感信息。
* **Social Engineering (社交工程)**: 想像一個攻擊者使用心理操縱來欺騙用戶提供敏感信息。技術上是指攻擊者使用心理操縱來欺騙用戶提供敏感信息。
* **Apple 帳戶變更通知**: Apple 的安全提醒通知機制，當用戶的帳戶信息發生變更時，Apple 會發送郵件通知用戶。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/apple-account-change-alerts-abused-to-send-phishing-emails/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


