---
layout: post
title:  "Device code phishing attacks surge 37x as new kits spread online"
date:   2026-04-04 18:32:21 +0000
categories: [security]
severity: high
---

# 🔥 解析 OAuth 2.0 Device Authorization Grant 流程中的設備代碼釣魚攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: Account Hijacking
> * **關鍵技術**: OAuth 2.0, Device Authorization Grant, Phishing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OAuth 2.0 Device Authorization Grant 流程中的設備代碼驗證機制存在漏洞，允許攻擊者通過釣魚手段取得設備代碼並劫持用戶帳戶。
* **攻擊流程圖解**:
  1. 攻擊者向服務提供者發送設備授權請求。
  2. 服務提供者返回設備代碼。
  3. 攻擊者將設備代碼發送給受害者。
  4. 受害者在合法登入頁面輸入設備代碼。
  5. 攻擊者的設備獲得授權，取得有效的存取和刷新令牌。
* **受影響元件**: OAuth 2.0 Device Authorization Grant 流程。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道受害者的電子郵件地址或其他聯繫信息。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 發送設備授權請求
    response = requests.post("https://example.com/device_authorization", data={"client_id": "client_id", "scope": "scope"})
    
    # 取得設備代碼
    device_code = response.json()["device_code"]
    
    # 將設備代碼發送給受害者
    print("請在以下網址輸入設備代碼：https://example.com/login")
    print("設備代碼：", device_code)
    
    ```
  *範例指令*: 使用 `curl` 發送設備授權請求。

```

bash
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=client_id&scope=scope" https://example.com/device_authorization

```
* **繞過技術**: 攻擊者可以使用 Phishing 技術來欺騙受害者輸入設備代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /device_authorization |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OAuth_Device_Authorization_Grant {
      meta:
        description = "OAuth 2.0 Device Authorization Grant 流程中的設備代碼驗證機制存在漏洞"
      strings:
        $device_code = "device_code"
      condition:
        $device_code
    }
    
    ```
  * 或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。

```

sql
index=security sourcetype=oauth2 device_code=*

```
* **緩解措施**: 除了 Patch 之外的 Config 修改建議，例如設定條件存取政策，監控設備代碼驗證事件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth 2.0**: 一種授權框架，允許用戶授權第三方應用程序存取其資源。
* **Device Authorization Grant**: 一種 OAuth 2.0 授權流程，允許設備授權存取資源。
* **Phishing**: 一種社交工程攻擊，欺騙用戶輸入敏感信息。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/device-code-phishing-attacks-surge-37x-as-new-kits-spread-online/)
- [OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)


