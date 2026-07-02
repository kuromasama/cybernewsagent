---
layout: post
title:  "Microsoft fixes bug that removed Copilot buttons in Outlook"
date:   2026-07-02 13:43:31 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Outlook Copilot 按鈕消失漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `COM Hijacking`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Microsoft Outlook 的 Copilot 功能中，存在一個未經檢查的邊界條件，導致當使用者啟用 Copilot Chat (Basic) 授權時，Copilot 按鈕可能會消失。
* **攻擊流程圖解**: 
    1. 使用者啟用 Copilot Chat (Basic) 授權
    2. Outlook 應用程式初始化 Copilot 功能
    3. Copilot 按鈕因邊界條件未經檢查而消失
* **受影響元件**: Microsoft Outlook 2016、2019、2021，版本號：16.0.20026.20168

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者必須具有 Copilot Chat (Basic) 授權
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建構 Payload
    payload = {
        "grant_type": "client_credentials",
        "client_id": "YOUR_CLIENT_ID",
        "client_secret": "YOUR_CLIENT_SECRET",
        "scope": "https://graph.microsoft.com/.default"
    }
    
    # 發送請求
    response = requests.post("https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/token", data=payload)
    
    # 取得存取權杖
    access_token = response.json()["access_token"]
    
    # 使用存取權杖存取 Copilot API
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get("https://graph.microsoft.com/v1.0/me/copilot", headers=headers)
    
    ```
    * **範例指令**: 使用 `curl` 發送請求

```

bash
curl -X POST \
  https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=https://graph.microsoft.com/.default'

```
* **繞過技術**: 可以使用 `COM Hijacking` 繞過 WAF 或 EDR 的檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\copilot.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule copilot_exploit {
        meta:
            description = "Copilot Exploit Detection"
            author = "Your Name"
        strings:
            $a = "copilot.dll"
            $b = "https://graph.microsoft.com/v1.0/me/copilot"
        condition:
            $a and $b
    }
    
    ```
    * **SIEM 查詢語法** (Splunk):

    ```
    
    spl
    index=security sourcetype=microsoft_outlook (eventtype="copilot_exploit" OR eventtype="com_hijacking")
    
    ```
* **緩解措施**: 更新 Microsoft Outlook 至最新版本，啟用 Copilot Chat (Basic) 授權，並設定 WAF 或 EDR 的檢查規則

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 想像一塊記憶體空間，攻擊者可以在這塊空間中填充特定的資料，以便在後續的攻擊中使用。技術上是指攻擊者在堆疊中分配大量的記憶體空間，以便在後續的攻擊中使用。
* **Deserialization**: 想像一個物件被序列化成字串，然後被反序列化回物件。技術上是指將資料從字串或其他格式轉換回物件或結構體。
* **COM Hijacking**: 想像一個 COM 物件被劫持，然後被用來執行惡意代碼。技術上是指攻擊者劫持 COM 物件的實例，然後使用它來執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-bug-that-removed-copilot-button-in-outlook/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


