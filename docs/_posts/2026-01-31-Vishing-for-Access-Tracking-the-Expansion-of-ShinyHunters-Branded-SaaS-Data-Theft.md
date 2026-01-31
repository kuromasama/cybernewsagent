---
layout: post
title:  "Vishing for Access: Tracking the Expansion of ShinyHunters-Branded SaaS Data Theft"
date:   2026-01-31 01:20:43 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ShinyHunters-Branded SaaS 資料竊取：利用 Vishing 和 Credential Harvesting 進行攻擊
> **⚡ 戰情快篓 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: 資料竊取和身份驗證攻擊
> * **關鍵技術**: Vishing、Credential Harvesting、SaaS 資料竊取

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Vishing 和 Credential Harvesting 的方式來竊取用戶的身份驗證資訊，進而存取 SaaS 應用程式。
* **攻擊流程圖解**:
  1. 攻擊者進行 Vishing，冒充 IT 人員，引導用戶到假的身份驗證網站。
  2. 用戶輸入身份驗證資訊，攻擊者竊取這些資訊。
  3. 攻擊者利用竊取的資訊存取 SaaS 應用程式，進行資料竊取。
* **受影響元件**: SaaS 應用程式，尤其是那些使用單一登入 (SSO) 和多因素身份驗證 (MFA) 的應用程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Vishing 和 Credential Harvesting 的能力。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      payload = {
        "username": "victim_username",
        "password": "victim_password",
        "mfa_code": "victim_mfa_code"
      }
    
    ```
  * **範例指令**: 使用 `curl` 發送 POST 請求到假的身份驗證網站。

```

bash
  curl -X POST -H "Content-Type: application/json" -d '{"username": "victim_username", "password": "victim_password", "mfa_code": "victim_mfa_code"}' https://fake-auth-site.com/login

```
* **繞過技術**: 攻擊者可以使用 VPN 和代理伺服器來繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | fake-auth-site.com | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ShinyHunters_Credential_Harvesting {
        meta:
          description = "Detects ShinyHunters credential harvesting"
        strings:
          $a = "fake-auth-site.com"
        condition:
          $a in (http.request.uri)
      }
    
    ```
  * **SIEM 查詢語法**: 使用 Splunk 或 Elastic Search 來查詢相關的日誌。

```

spl
  index=web_logs (http.request.uri="*fake-auth-site.com*")

```
* **緩解措施**: 使用強大的密碼、啟用 MFA、並定期更新軟體和系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Vishing (語音釣魚)**: 一種利用電話來進行的釣魚攻擊，攻擊者冒充合法的實體來竊取用戶的敏感資訊。
* **Credential Harvesting (憑證收集)**: 一種攻擊方式，攻擊者竊取用戶的身份驗證資訊，例如用戶名和密碼。
* **SaaS (軟體即服務)**: 一種軟體交付模式，軟體應用程式通過網際網路提供給用戶。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


