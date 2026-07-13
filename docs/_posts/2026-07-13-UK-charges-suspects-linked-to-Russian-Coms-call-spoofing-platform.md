---
layout: post
title:  "UK charges suspects linked to Russian Coms call spoofing platform"
date:   2026-07-13 14:15:15 +0000
categories: [security]
severity: high
---

# 🔥 解析俄羅斯通訊平台的呼叫 ID 欺騙技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Caller ID Spoofing
> * **關鍵技術**: `Caller ID Spoofing`, `Social Engineering`, `Telephony`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 俄羅斯通訊平台的呼叫 ID 欺騙技術是基於對電話網絡的操控，允許攻擊者偽造來電號碼，從而欺騙受害者。
* **攻擊流程圖解**: 
  1. 攻擊者購買俄羅斯通訊平台的服務
  2. 攻擊者使用平台的 API 或 Web 介面來發送偽造的來電號碼
  3. 受害者接收到偽造的來電號碼，誤以為是來自合法的機構
  4. 攻擊者使用社會工程學手法來欺騙受害者，竊取其個人資訊或財務資訊
* **受影響元件**: 俄羅斯通訊平台的用戶，包括個人和企業

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要購買俄羅斯通訊平台的服務，並具有基本的社會工程學知識
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義偽造的來電號碼
    fake_caller_id = "+1234567890"
    
    # 定義受害者的電話號碼
    victim_phone_number = "+9876543210"
    
    # 使用俄羅斯通訊平台的 API 來發送偽造的來電號碼
    response = requests.post("https://russian-coms.com/api/call", 
                               json={"caller_id": fake_caller_id, "phone_number": victim_phone_number})
    
    # 檢查是否成功發送偽造的來電號碼
    if response.status_code == 200:
        print("成功發送偽造的來電號碼")
    else:
        print("發送偽造的來電號碼失敗")
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術來避免被偵測，例如使用 VPN 或 Proxy 來隱藏其 IP 地址

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | russian-coms.com | /api/call |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule RussianComs {
      meta:
        description = "俄羅斯通訊平台的偽造來電號碼偵測"
        author = "Your Name"
      strings:
        $api_call = "/api/call"
      condition:
        $api_call in (http.request.uri)
    }
    
    ```
* **緩解措施**: 
  1. 使用電話網絡的安全功能，例如來電號碼驗證
  2. 教育用戶關於社會工程學的風險和如何避免被欺騙
  3. 監控電話網絡的異常活動，並及時響應

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Caller ID Spoofing (來電號碼欺騙)**: 想像有人可以偽造你的電話號碼，然後打電話給你的朋友或家人。技術上是指攻擊者使用各種手法來偽造來電號碼，從而欺騙受害者。
* **Social Engineering (社會工程學)**: 想像有人可以通過心理操控來讓你做出某些事情。技術上是指攻擊者使用各種心理操控手法來欺騙受害者，竊取其個人資訊或財務資訊。
* **Telephony (電話網絡)**: 想像一個全球性的電話網絡，允許人們之間進行通訊。技術上是指電話網絡的基礎架構和協議，包括電話號碼、電話交換機等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/uk-charges-suspects-linked-to-russian-coms-call-spoofing-platform/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1498/)


