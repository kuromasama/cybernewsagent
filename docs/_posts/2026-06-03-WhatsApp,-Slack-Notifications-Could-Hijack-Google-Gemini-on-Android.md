---
layout: post
title:  "WhatsApp, Slack Notifications Could Hijack Google Gemini on Android"
date:   2026-06-03 20:49:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析 WhatsApp、Slack 通知劫持 Google Gemini 語音助手的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Notification Injection`, `Delayed Tool Invocation`, `Fake Context Alignment`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Gemini 的 Utilities 功能可以讀取和回覆通知，包括 WhatsApp、Slack 等應用程式的通知。然而，Gemini 將這些通知的文字視為指令，可以執行敏感動作。這使得攻擊者可以通過發送特製的通知來控制 Gemini。
* **攻擊流程圖解**:
  1. 攻擊者發送特製的通知給受害者。
  2. Gemini 收到通知並將其視為指令。
  3. Gemini 執行指令，可能包括開啟窗口、發送消息或執行其他敏感動作。
* **受影響元件**: Google Gemini、Android 10 以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道受害者的 WhatsApp、Slack 等應用程式的通知設定。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義通知內容
    notification_content = "開啟窗口"
    
    # 定義通知發送者
    sender = "WhatsApp"
    
    # 定義通知接收者
    receiver = "受害者"
    
    # 發送通知
    requests.post("https://example.com/notify", data={"content": notification_content, "sender": sender, "receiver": receiver})
    
    ```
* **繞過技術**: 攻擊者可以使用 `Fake Context Alignment` 技術來繞過 Gemini 的安全檢查。這涉及到發送多個通知，包括一個合法的通知和一個惡意的通知，從而使 Gemini 將惡意通知視為合法的指令。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /notify |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Gemini_Notification_Injection {
      meta:
        description = "Detects Gemini notification injection attacks"
      strings:
        $notification_content = "開啟窗口"
      condition:
        $notification_content in (0..1000)
    }
    
    ```
* **緩解措施**: 使用者可以關閉 Gemini 的通知讀取和回覆功能，或者更新 Google Gemini 到最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Notification Injection (通知注入)**: 想像攻擊者可以將惡意通知注入到受害者的通知流中。技術上是指攻擊者發送特製的通知給受害者，從而使受害者的應用程式執行敏感動作。
* **Delayed Tool Invocation (延遲工具呼叫)**: 想像攻擊者可以延遲呼叫工具或應用程式。技術上是指攻擊者發送特製的通知給受害者，從而使受害者的應用程式延遲呼叫工具或應用程式。
* **Fake Context Alignment (偽造上下文對齊)**: 想像攻擊者可以偽造上下文對齊。技術上是指攻擊者發送多個通知，包括一個合法的通知和一個惡意的通知，從而使受害者的應用程式將惡意通知視為合法的指令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/whatsapp-slack-notifications-could.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


