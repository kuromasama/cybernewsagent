---
layout: post
title:  "Turning IBM QRadar Alerts into Action with Criminal IP"
date:   2026-02-13 18:38:20 +0000
categories: [security]
severity: high
---

# 🔥 解析 Criminal IP 與 IBM QRadar SIEM/SOAR 整合：提升威脅偵測與應對能力

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.0)
> * **受駭指標**: 高風險 IP 地址、惡意流量
> * **關鍵技術**: AI 驅動的威脅智慧、OSINT、API 整合

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Criminal IP 與 IBM QRadar SIEM/SOAR 整合的目的是為了提升威脅偵測與應對能力，透過 AI 驅動的威脅智慧與 OSINT 來分析流量日誌並自動評估風險。
* **攻擊流程圖解**: 
    1. 收集流量日誌
    2. 透過 Criminal IP API 分析流量日誌
    3. 自動評估風險並分類為高、中、低風險
    4. 將風險評估結果反饋到 QRadar SIEM/SOAR
* **受影響元件**: IBM QRadar SIEM/SOAR、Criminal IP

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有權限存取 QRadar SIEM/SOAR 與 Criminal IP
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 API endpoint 與 API key
    endpoint = "https://api.criminalip.io/v1/ip"
    api_key = "YOUR_API_KEY"
    
    # 定義要查詢的 IP 地址
    ip_address = "192.0.2.1"
    
    # 建構 API 請求
    headers = {"Authorization": f"Bearer {api_key}"}
    params = {"ip": ip_address}
    
    # 送出 API 請求
    response = requests.get(endpoint, headers=headers, params=params)
    
    # 處理 API 回應
    if response.status_code == 200:
        print("IP 地址風險評估結果：", response.json())
    else:
        print("錯誤：", response.status_code)
    
    ```
    *範例指令*: 使用 `curl` 送出 API 請求

```

bash
curl -X GET \
  https://api.criminalip.io/v1/ip \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d 'ip=192.0.2.1'

```
* **繞過技術**: 無

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 192.0.2.1 | example.com | /var/log/traffic.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Criminal_IP_Detection {
        meta:
            description = "Criminal IP 風險評估結果"
            author = "Your Name"
        strings:
            $ip_address = "192.0.2.1"
        condition:
            $ip_address
    }
    
    ```
    或者是使用 Splunk 查詢語法

```

spl
index=traffic_log ip_address="192.0.2.1"

```
* **緩解措施**: 
    1. 更新 QRadar SIEM/SOAR 與 Criminal IP 到最新版本
    2. 啟用 API 驗證與授權
    3. 監控流量日誌並設定警報

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AI 驅動的威脅智慧 (AI-Powered Threat Intelligence)**: 使用人工智慧技術來分析與評估威脅情報，提供更準確與即時的威脅偵測能力。
* **OSINT (公開來源情報)**: 收集與分析公開來源的情報，例如社交媒體、新聞報導等，來評估威脅風險。
* **API 整合 (API Integration)**: 將不同的系統或服務整合在一起，透過 API 來交換資料與提供功能。

## 5. 🔗 參考文獻與延伸閱讀
- [Criminal IP 官方網站](https://www.criminalip.io/)
- [IBM QRadar SIEM/SOAR 官方網站](https://www.ibm.com/security/products/security-information-event-management)
- [MITRE ATT&CK 框架](https://attack.mitre.org/)


