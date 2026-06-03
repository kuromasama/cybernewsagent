---
layout: post
title:  "Google adds Android protection against AI deepfake scam calls"
date:   2026-06-03 10:47:40 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Android 新增的「偽造電話偵測」功能：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Spoofing
> * **關鍵技術**: Rich Communication Services (RCS), Phone by Google, Google Messages

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 偽造電話偵測功能是基於 Rich Communication Services (RCS) 的開放標準，利用 Phone by Google、Contacts 和 Google Messages (啟用 RCS) 進行實時驗證。
* **攻擊流程圖解**:
  1. Scammer 使用 AI 技術偽造用戶的聯繫人。
  2. 偽造電話呼叫發送給用戶。
  3. 用戶的設備接收到呼叫，啟動偽造電話偵測功能。
  4. 偽造電話偵測功能向聯繫人的實際設備發送驗證請求。
  5. 如果聯繫人的實際設備確認沒有進行呼叫，則用戶的設備會顯示警告訊息。
* **受影響元件**: Android 12 及以上版本，Phone by Google、Contacts 和 Google Messages (啟用 RCS)。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Scammer 需要使用 AI 技術偽造用戶的聯繫人，並且需要知道用戶的電話號碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Scammer 的電話號碼
    scammer_phone_number = "+1234567890"
    
    # 用戶的電話號碼
    user_phone_number = "+9876543210"
    
    # 偽造電話呼叫的 URL
    url = f"https://example.com/call?from={scammer_phone_number}&to={user_phone_number}"
    
    # 發送偽造電話呼叫請求
    response = requests.post(url)
    
    # 檢查是否成功
    if response.status_code == 200:
        print("偽造電話呼叫成功")
    else:
        print("偽造電話呼叫失敗")
    
    ```
* **繞過技術**: Scammer 可以嘗試使用其他方法來繞過偽造電話偵測功能，例如使用不同的電話號碼或是利用其他漏洞。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /call |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule fake_call_detection {
        meta:
            description = "偵測偽造電話呼叫"
            author = "Your Name"
        strings:
            $url = "https://example.com/call"
        condition:
            $url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 用戶可以啟用 Phone by Google、Contacts 和 Google Messages (啟用 RCS) 來啟用偽造電話偵測功能。此外，用戶也可以使用其他安全措施，例如驗證聯繫人的身份和使用安全的通訊軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Rich Communication Services (RCS)**: 一種開放標準的即時通訊協議，允許用戶之間進行文字、圖片和語音通訊。
* **Phone by Google**: 一款由 Google 開發的電話應用程式，提供了多種功能，包括偽造電話偵測。
* **Google Messages**: 一款由 Google 開發的短信應用程式，支持 RCS 協議。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/google-adds-android-protection-against-ai-deepfake-scam-calls/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1192/)


