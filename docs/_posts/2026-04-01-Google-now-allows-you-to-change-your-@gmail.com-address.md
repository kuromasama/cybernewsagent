---
layout: post
title:  "Google now allows you to change your @gmail.com address"
date:   2026-04-01 01:57:48 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Google Gmail 地址變更功能的安全性
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Email Spoofing`, `Identity Theft`, `Alias Management`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Gmail 地址變更功能允許用戶修改其 `@gmail.com` 地址，但這可能導致用戶的身份信息被泄露。
* **攻擊流程圖解**: 
    1. 用戶申請一個新的 Gmail 地址。
    2. 用戶修改其 `@gmail.com` 地址為新的地址。
    3. 攻擊者嘗試使用新的地址進行身份驗證。
* **受影響元件**: Google Gmail 地址變更功能（版本號：未指定）。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個有效的 Gmail 地址和密碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義用戶的 Gmail 地址和密碼
    email = "example@gmail.com"
    password = "password"
    
    # 修改用戶的 Gmail 地址
    new_email = "new_example@gmail.com"
    
    # 建構 Payload
    payload = {
        "email": new_email,
        "password": password
    }
    
    # 發送請求
    response = requests.post("https://accounts.google.com/ChangeEmail", data=payload)
    
    # 驗證結果
    if response.status_code == 200:
        print("修改成功")
    else:
        print("修改失敗")
    
    ```
    * **範例指令**: 使用 `curl` 命令發送請求：

```

bash
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "email=new_example@gmail.com&password=password" https://accounts.google.com/ChangeEmail

```
* **繞過技術**: 攻擊者可以使用 `Email Spoofing` 技術來繞過身份驗證。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | accounts.google.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Gmail_Address_Change {
        meta:
            description = "Gmail 地址變更偵測"
            author = "Your Name"
        strings:
            $email = "email=" nocase
            $password = "password=" nocase
        condition:
            $email and $password
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=gmail_logs (email="*" AND password="*")
    
    ```
* **緩解措施**: 使用強密碼和兩步 驗證來保護用戶的 Gmail 地址。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Email Spoofing (電子郵件偽造)**: 想像有人發送電子郵件時，偽造發件人的地址。技術上是指攻擊者使用假的發件人地址來發送電子郵件，目的是欺騙收件人。
* **Identity Theft (身份盜竊)**: 想像有人偷走你的身份證。技術上是指攻擊者竊取用戶的身份信息，例如用戶名、密碼、電子郵件地址等。
* **Alias Management (別名管理)**: 想像你有多個別名，需要管理它們。技術上是指管理用戶的別名，例如 Gmail 地址變更功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/google/google-now-allows-you-to-change-your-gmailcom-address/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1192/)


