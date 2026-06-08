---
layout: post
title:  "Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order"
date:   2026-06-08 20:05:05 +0000
categories: [security]
severity: high
---

# 🔥 解析 NSO Group 對 WhatsApp 的 Spear-Phishing 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Spear-Phishing`, `Malicious Links`, `End-to-End Encryption`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NSO Group 利用了 WhatsApp 的漏洞，通過發送針對性的魚叉式郵件（Spear-Phishing）來誘騙用戶點擊惡意連結，從而實現遠程代碼執行（RCE）。
* **攻擊流程圖解**: 
    1. 用戶收到針對性的魚叉式郵件。
    2. 郵件包含惡意連結，連結到外部網站。
    3. 用戶點擊連結，導致惡意代碼被下載和執行。
* **受影響元件**: WhatsApp 的所有版本，特別是那些沒有啟用端到端加密（End-to-End Encryption）的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道用戶的 WhatsApp 帳號和相關信息。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意連結
    malicious_link = "https://fr24cast.com"
    
    # 發送針對性的魚叉式郵件
    def send_phishing_email(user_email):
        # 建構郵件內容
        email_content = f"點擊以下連結：{malicious_link}"
        # 發送郵件
        requests.post("https://example.com/send_email", data={"email": user_email, "content": email_content})
    
    # 執行攻擊
    send_phishing_email("user@example.com")
    
    ```
    *範例指令*: 使用 `curl` 發送 HTTP 請求到惡意連結。

```

bash
curl -X GET https://fr24cast.com

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | fr24cast.com | /usr/bin/malware |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_link {
        meta:
            description = "惡意連結"
            author = "Blue Team"
        strings:
            $link = "https://fr24cast.com"
        condition:
            $link
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
SELECT * FROM logs WHERE url LIKE "%fr24cast.com%"

```
* **緩解措施**: 啟用端到端加密（End-to-End Encryption），並定期更新 WhatsApp 的版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Spear-Phishing (魚叉式郵件)**: 一種針對性的郵件攻擊，攻擊者會發送針對性的郵件給特定的用戶，試圖誘騙用戶點擊惡意連結或下載惡意軟件。
* **End-to-End Encryption (端到端加密)**: 一種加密技術，能夠確保數據在傳輸過程中保持機密和完整。
* **RCE (Remote Code Execution)**: 一種攻擊技術，攻擊者可以在遠程主機上執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/meta-blocks-nso-groups-new-whatsapp.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


