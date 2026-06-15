---
layout: post
title:  "SimpleHelp bug lets hackers create rogue remote support accounts"
date:   2026-06-15 20:50:31 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SimpleHelp 遠端管理軟體的 OIDC 身份驗證漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: Unauthenticated attackers can create privileged technician accounts
> * **關鍵技術**: OIDC 身份驗證、 Technician Group、Allow group authenticated logins

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SimpleHelp 遠端管理軟體的 OIDC 身份驗證機制存在漏洞，允許未經驗證的攻擊者創建具有特權的技術人員帳戶。
* **攻擊流程圖解**:
  1. 攻擊者啟用 OIDC 身份驗證
  2. 攻擊者創建一個新的 Technician Group 並將其與 OIDC 身份提供者關聯
  3. 攻擊者啟用 "Allow group authenticated logins" 選項
  4. 攻擊者使用 OIDC 身份提供者進行身份驗證並創建一個新的技術人員帳戶
* **受影響元件**: SimpleHelp 版本 5.5.15 和更早版本，以及 6.0 預發布版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: OIDC 身份驗證必須啟用，至少有一個 Technician Group 與 OIDC 身份提供者關聯，且 "Allow group authenticated logins" 選項必須啟用
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # OIDC 身份提供者 URL
    oidc_url = "https://example.com/oidc"
    
    # Technician Group 名稱
    group_name = "example_group"
    
    # 創建新的技術人員帳戶
    response = requests.post(
        f"{oidc_url}/api/v1/technicians",
        json={"name": "example_technician", "email": "example@example.com", "group": group_name}
    )
    
    # 驗證響應
    if response.status_code == 201:
        print("技術人員帳戶創建成功")
    else:
        print("技術人員帳戶創建失敗")
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用不同的 HTTP 方法或添加無關的參數

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | example.com |
| File Path | /opt/SimpleHelp/logs/server.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SimpleHelp_Technician_Creation {
      meta:
        description = "偵測 SimpleHelp 技術人員帳戶創建"
        author = "Your Name"
      strings:
        $oidc_url = "https://example.com/oidc"
        $group_name = "example_group"
      condition:
        http.request.uri == $oidc_url + "/api/v1/technicians" and
        http.request.body contains $group_name
    }
    
    ```
* **緩解措施**: 更新 SimpleHelp 至最新版本，限制技術人員登入來源使用 IP-based allowlists

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OIDC (OpenID Connect)**: 一種身份驗證協議，允許用戶使用單一身份驗證多個應用程序
* **Technician Group**: SimpleHelp 中的一個概念，代表一組具有特權的技術人員
* **Allow group authenticated logins**: 一個選項，允許 Technician Group 中的技術人員使用 OIDC 身份驗證進行登入

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/simplehelp-bug-lets-hackers-create-rogue-remote-support-accounts/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


