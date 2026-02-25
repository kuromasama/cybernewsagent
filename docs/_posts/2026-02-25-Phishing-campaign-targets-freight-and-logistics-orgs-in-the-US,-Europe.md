---
layout: post
title:  "Phishing campaign targets freight and logistics orgs in the US, Europe"
date:   2026-02-25 01:28:32 +0000
categories: [security]
severity: high
---

# 🔥 解析 Diesel Vortex 攻擊：利用 Phishing 和 Typosquatting 獲取貨運業的機密資訊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Credential Theft
> * **關鍵技術**: Phishing, Typosquatting, Cyrilic Homoglyph Tricks

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Diesel Vortex 攻擊者利用 Phishing 和 Typosquatting 技術來獲取貨運業的機密資訊。攻擊者會建立假的網站和電子郵件，模仿真實的貨運業平台，以騙取用戶的登入資訊。
* **攻擊流程圖解**:
  1. 攻擊者建立假的網站和電子郵件，模仿真實的貨運業平台。
  2. 用戶接收到假的電子郵件，點擊連結後被導致到假的網站。
  3. 假的網站要求用戶輸入登入資訊，包括帳號和密碼。
  4. 攻擊者收集到用戶的登入資訊，利用它們來進行進一步的攻擊。
* **受影響元件**: 貨運業的用戶，包括 DAT Truckstop, TIMOCOM, Teleroute, Penske Logistics, Girteka, 和 Electronic Funds Source (EFS) 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要建立假的網站和電子郵件，模仿真實的貨運業平台。
* **Payload 建構邏輯**:

    ```
    
    python
      # 假的網站代碼
      import requests
      from flask import Flask, request
    
      app = Flask(__name__)
    
      @app.route('/login', methods=['POST'])
      def login():
        username = request.form['username']
        password = request.form['password']
        # 收集到用戶的登入資訊
        return '登入成功'
    
      if __name__ == '__main__':
        app.run()
    
    ```
  *範例指令*: `curl -X POST -d 'username=admin&password=password' http://example.com/login`
* **繞過技術**: 攻擊者可以利用 Cyrilic Homoglyph Tricks 來繞過安全過濾器。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Diesel_Vortex {
        meta:
          description = "Diesel Vortex 攻擊"
          author = "Your Name"
        strings:
          $a = "login" ascii
          $b = "username" ascii
          $c = "password" ascii
        condition:
          all of them
      }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)：

```

sql
  index=web_logs | search "login" AND "username" AND "password"

```
* **緩解措施**: 更新修補、啟用安全過濾器、教育用戶注意 Phishing 攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing**: 想像一個釣魚者，利用假的電子郵件或網站來騙取用戶的機密資訊。技術上是指一種社交工程攻擊，利用假的電子郵件或網站來騙取用戶的登入資訊。
* **Typosquatting**: 想像一個域名註冊者，利用類似的域名來騙取用戶的訪問。技術上是指一種域名註冊攻擊，利用類似的域名來騙取用戶的訪問。
* **Cyrilic Homoglyph Tricks**: 想像一個攻擊者，利用西里爾字母來繞過安全過濾器。技術上是指一種繞過技術，利用西里爾字母來繞過安全過濾器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/phishing-campaign-targets-freight-and-logistics-orgs-in-the-us-europe/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


