---
layout: post
title:  "資安研究人員揭露Google Vertex AI權限設計缺陷，可能導致雲端資料外洩"
date:   2026-04-01 13:06:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 Google Vertex AI 權限設計缺陷：利用與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Privilege Escalation
> * **關鍵技術**: Over-Privileged, Principle of Least Privilege, Service Account

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Vertex AI 預設服務帳戶的服務代理（Per-Project, Per-Product Service Agent，P4SA）被授予過大的權限，導致攻擊者可以存取用戶敏感資料。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個 Vertex AI 專案
    2. 預設服務帳戶的服務代理被授予過大的權限
    3. 攻擊者利用服務代理存取用戶敏感資料
* **受影響元件**: Google Vertex AI

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Vertex AI 專案的存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義服務代理的憑證
    service_account_credentials = {
        'client_email': 'your-service-account-email',
        'private_key': 'your-private-key'
    }
    
    # 存取用戶敏感資料
    response = requests.get('https://your-vertex-ai-project.com/data', auth=service_account_credentials)
    
    print(response.text)
    
    ```
    * **範例指令**: 使用 `curl` 命令存取用戶敏感資料

```

bash
curl -X GET \
  https://your-vertex-ai-project.com/data \
  -H 'Authorization: Bearer your-service-account-token'

```
* **繞過技術**: 攻擊者可以利用服務代理的憑證存取用戶敏感資料，即使 WAF 或 EDR 有設定也可以繞過

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | your-vertex-ai-project.com | /data |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule vertex_ai_service_account_abuse {
        meta:
            description = "Detects Vertex AI service account abuse"
            author = "Your Name"
        strings:
            $service_account_credentials = "client_email" wide
            $private_key = "private_key" wide
        condition:
            $service_account_credentials and $private_key
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=your-index-name (service_account_credentials OR private_key)
    
    ```
* **緩解措施**: 使用自定服務帳戶（Custom Service Account）以便覆蓋預設帳戶權限，強制執行最小權限原則（Principle of Least Privilege）

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Service Account (服務帳戶)**: 一種特殊的帳戶，用於代表服務或應用程式存取其他服務或資源。技術上是指一種可以存取其他服務或資源的身份。
* **Principle of Least Privilege (最小權限原則)**: 一種安全原則，指的是只授予必要的權限給服務或應用程式，以減少安全風險。
* **Over-Privileged (過度授權)**: 一種安全風險，指的是服務或應用程式被授予過大的權限，導致攻擊者可以存取敏感資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174833)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1078/)


