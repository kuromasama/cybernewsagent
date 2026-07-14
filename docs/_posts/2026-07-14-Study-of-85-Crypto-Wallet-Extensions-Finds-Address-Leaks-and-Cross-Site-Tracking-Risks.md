---
layout: post
title:  "Study of 85 Crypto Wallet Extensions Finds Address Leaks and Cross-Site Tracking Risks"
date:   2026-07-14 13:17:07 +0000
categories: [security]
severity: high
---

# 🔥 解析加密錢包瀏覽器擴充功能的隱私漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Web3, Blockchain, Wallet Extension

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 加密錢包瀏覽器擴充功能在與網站和區塊鏈伺服器交互時，會洩露用戶的地址和其他敏感資訊。
* **攻擊流程圖解**:
  1. 用戶安裝加密錢包瀏覽器擴充功能。
  2. 擴充功能將用戶的地址和其他資訊發送給網站和區塊鏈伺服器。
  3. 攻擊者可以截取這些資訊，將用戶的地址和其他敏感資訊與真實身份聯繫起來。
* **受影響元件**: 85 個加密錢包瀏覽器擴充功能，包括 Coinbase Wallet、MetaMask 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制網站或區塊鏈伺服器。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 發送請求給網站或區塊鏈伺服器
    response = requests.get('https://example.com/api/wallet-info')
    
    # 解析回應中的用戶地址和其他敏感資訊
    user_address = response.json()['address']
    
    ```
* **繞過技術**: 攻擊者可以使用隱碼或其他技術來繞過瀏覽器的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /api/wallet-info |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule wallet_leak {
      meta:
        description = "Detect wallet leak"
      strings:
        $a = "wallet-info"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 用戶可以清除瀏覽器的緩存和 Cookie，同時使用不同的瀏覽器或瀏覽器配置文件來分隔不同的活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Web3**: 一種基於區塊鏈技術的網路應用程序。
* **Blockchain**: 一種分佈式的數據儲存和傳輸技術。
* **Wallet Extension**: 一種瀏覽器擴充功能，允許用戶管理其加密貨幣和其他數字資產。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/study-of-85-crypto-wallet-extensions.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


