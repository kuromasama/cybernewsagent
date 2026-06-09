---
layout: post
title:  "Investigating suspicious AI workflows in Microsoft Entra Agent ID: Assistive agents"
date:   2026-06-09 02:33:08 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Entra Agent ID 的 On-Behalf-Of 流程與攻防技術
> **⚡ 戰情快篓 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Assistive Agents 的 On-Behalf-Of 流程可能被利用進行未經授權的郵件發送
> * **關鍵技術**: On-Behalf-Of (OBO) 流程、Microsoft Entra Agent ID、Microsoft Graph API

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Entra Agent ID 的 On-Behalf-Of 流程允許助理代理 (Assistive Agents) 代替使用者執行特定任務，但如果攻擊者獲得了代理的授權，可能會利用這個流程進行未經授權的郵件發送。
* **攻擊流程圖解**: 
    1. 攻擊者獲得代理的授權。
    2. 攻擊者使用代理的授權發送郵件。
* **受影響元件**: Microsoft Entra Agent ID、Microsoft Graph API

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得代理的授權。
* **Payload 建構邏輯**: 
    * 攻擊者可以使用 Microsoft Graph API 發送郵件。
    * *範例指令*: `curl -X POST https://graph.microsoft.com/v1.0/me/sendMail -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"message": {"subject": "Test Email", "body": {"content": "This is a test email"}, "toRecipients": [{"emailAddress": {"address": "recipient@example.com"}}]}}'`
* **繞過技術**: 攻擊者可以使用各種方法繞過授權機制，例如使用已經授權的代理或利用授權漏洞。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 描述 |
| --- | --- |
| `https://graph.microsoft.com/v1.0/me/sendMail` | Microsoft Graph API 發送郵件端點 |
| `Authorization: Bearer <token>` | 授權令牌 |* **偵測規則 (Detection Rules)**:
    * YARA Rule: `rule MicrosoftGraphAPISendMail { meta: description = "Microsoft Graph API 發送郵件" condition: $a = "https://graph.microsoft.com/v1.0/me/sendMail" }`
    * Snort/Suricata Signature: `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Microsoft Graph API 發送郵件"; content:"https://graph.microsoft.com/v1.0/me/sendMail"; sid:1000001; rev:1;)`
* **緩解措施**: 
    * 監控 Microsoft Graph API 的授權請求。
    * 限制代理的授權範圍。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **On-Behalf-Of (OBO) 流程**: 一種授權機制，允許代理代替使用者執行特定任務。
* **Microsoft Entra Agent ID**: 一種代理身份驗證系統，允許代理代替使用者執行特定任務。
* **Microsoft Graph API**: 一種 API，提供了對 Microsoft 服務的存取，包括郵件發送。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-detection/entra-id-ai-workflows-assistive-agents/)
- [Microsoft Entra Agent ID 文件](https://docs.microsoft.com/en-us/azure/active-directory/develop/entra-agent-id)
- [Microsoft Graph API 文件](https://docs.microsoft.com/en-us/graph/)


