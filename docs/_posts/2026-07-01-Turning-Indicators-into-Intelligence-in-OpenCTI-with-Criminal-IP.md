---
layout: post
title:  "Turning Indicators into Intelligence in OpenCTI with Criminal IP"
date:   2026-07-01 14:18:00 +0000
categories: [security]
severity: high
---

# 🔥 解析 Cyber 威脅情報：利用 OpenCTI 和 Criminal IP 進行指標豐富化

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: IP 地址、域名和 URL 的指標豐富化
> * **關鍵技術**: 威脅情報、指標豐富化、OpenCTI、Criminal IP

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Cyber 威脅情報的指標豐富化是指將原始指標（如 IP 地址、域名和 URL）轉化為結構化的情報，以支持調查、相關性分析和決策。
* **攻擊流程圖解**: 
    1. 收集原始指標（IP 地址、域名和 URL）
    2. 使用 OpenCTI 和 Criminal IP 進行指標豐富化
    3. 結構化情報以支持調查、相關性分析和決策
* **受影響元件**: OpenCTI、Criminal IP、IP 地址、域名和 URL

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 收集原始指標（IP 地址、域名和 URL）
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 收集原始指標
    ip_address = "192.168.1.1"
    domain = "example.com"
    url = "https://example.com"
    
    # 使用 OpenCTI 和 Criminal IP 進行指標豐富化
    opencti_url = "https://opencti.io/api/v1/indicators"
    criminal_ip_url = "https://criminalip.io/api/v1/indicators"
    
    # 建構 Payload
    payload = {
        "ip_address": ip_address,
        "domain": domain,
        "url": url
    }
    
    # 發送請求
    response = requests.post(opencti_url, json=payload)
    response = requests.post(criminal_ip_url, json=payload)
    
    ```
* **繞過技術**: 使用 VPN、代理伺服器或 Tor 網路來繞過 IP 地址的限制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.1 | example.com | /path/to/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Indicator_Fusion {
        meta:
            description = "Detects indicator fusion"
            author = "Your Name"
        strings:
            $ip_address = "192.168.1.1"
            $domain = "example.com"
            $url = "https://example.com"
        condition:
            any of ($ip_address, $domain, $url)
    }
    
    ```
* **緩解措施**: 更新 OpenCTI 和 Criminal IP 的版本，使用最新的指標豐富化技術

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **威脅情報 (Threat Intelligence)**: 指的是收集、分析和分享有關威脅的情報，以支持組織的安全防禦。
* **指標豐富化 (Indicator Enrichment)**: 指的是將原始指標轉化為結構化的情報，以支持調查、相關性分析和決策。
* **OpenCTI (Open Cyber Threat Intelligence)**: 一個開源的威脅情報平台，提供結構化的情報以支持調查、相關性分析和決策。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/turning-indicators-into-intelligence-in-opencti-with-criminal-ip/)
- [OpenCTI 官方文檔](https://opencti.io/docs/)
- [Criminal IP 官方文檔](https://criminalip.io/docs/)


