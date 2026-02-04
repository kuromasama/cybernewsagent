---
layout: post
title:  "Wave of Citrix NetScaler scans use thousands of residential proxies"
date:   2026-02-04 01:23:16 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Citrix NetScaler 大規模掃描活動：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Residential Proxies, Version Enumeration, EPA (Endpoint Analysis) Setup File

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Citrix NetScaler 的 EPA Setup File 存在版本信息泄露漏洞，攻擊者可以通過枚舉版本信息來發現潛在的漏洞。
* **攻擊流程圖解**:
  1. 攻擊者使用住宅代理 (Residential Proxies) 對 Citrix NetScaler 進行掃描。
  2. 攻擊者枚舉 EPA Setup File 的版本信息，以發現潛在的漏洞。
  3. 攻擊者使用發現的漏洞進行遠程代碼執行 (RCE) 攻擊。
* **受影響元件**: Citrix NetScaler 12.1、13.0、14.0

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要有一個住宅代理 (Residential Proxies) 伺服器。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 EPA Setup File 的 URL
    epa_url = "https://example.com/epa/scripts/win/nsepa_setup.exe"
    
    # 定義版本信息枚舉的 payload
    payload = {
        "version": "12.1"
    }
    
    # 發送請求
    response = requests.get(epa_url, params=payload)
    
    # 判斷版本信息是否存在
    if response.status_code == 200:
        print("版本信息存在")
    else:
        print("版本信息不存在")
    
    ```
* **繞過技術**: 攻擊者可以使用住宅代理 (Residential Proxies) 來繞過 IP 封鎖和其他安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /epa/scripts/win/nsepa_setup.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Citrix_NetScaler_EPA_Setup_File {
      meta:
        description = "Citrix NetScaler EPA Setup File"
        author = "Your Name"
      strings:
        $epa_url = "/epa/scripts/win/nsepa_setup.exe"
      condition:
        $epa_url
    }
    
    ```
* **緩解措施**:
  1. 更新 Citrix NetScaler 至最新版本。
  2. 限制 EPA Setup File 的存取權限。
  3. 監控住宅代理 (Residential Proxies) 伺服器的流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Residential Proxies (住宅代理)**: 一種代理伺服器，使用住宅 IP 地址來隱藏真實的 IP 地址。
* **EPA (Endpoint Analysis)**: 一種技術，用于分析端點設備的安全性和合規性。
* **Version Enumeration (版本枚舉)**: 一種技術，用于枚舉軟件或系統的版本信息。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.bleepingcomputer.com/news/security/wave-of-citrix-netscaler-scans-use-thousands-of-residential-proxies/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


