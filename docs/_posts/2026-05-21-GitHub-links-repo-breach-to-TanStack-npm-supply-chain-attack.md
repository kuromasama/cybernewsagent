---
layout: post
title:  "GitHub links repo breach to TanStack npm supply-chain attack"
date:   2026-05-21 09:27:18 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GitHub 供應鏈攻擊：Nx Console 擴充功能漏洞利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Supply Chain Attack, Malicious Extension, Credential Theft

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Nx Console 擴充功能的 18.95.0 版本中存在一個安全漏洞，允許攻擊者注入惡意代碼，從而竊取使用者憑證和秘密。
* **攻擊流程圖解**:
  1. 攻擊者將惡意版本的 Nx Console 擴充功能上傳到 Visual Studio Marketplace。
  2. 使用者安裝了惡意版本的 Nx Console 擴充功能。
  3. 攻擊者利用惡意代碼竊取使用者憑證和秘密。
* **受影響元件**: Nx Console 擴充功能 18.95.0 版本，Visual Studio Code。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要將惡意版本的 Nx Console 擴充功能上傳到 Visual Studio Marketplace。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意代碼
    def steal_credentials():
      # 竊取使用者憑證和秘密
      credentials = requests.get('https://example.com/credentials')
      return credentials.json()
    
    # 上傳惡意版本的 Nx Console 擴充功能
    def upload_malicious_extension():
      # 上傳惡意版本的 Nx Console 擴充功能到 Visual Studio Marketplace
      requests.post('https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisherName}/extensions/{extensionName}/versions/{version}', json={'extension': 'malicious_extension'})
    
    # 執行惡意代碼
    def execute_malicious_code():
      # 執行惡意代碼
      steal_credentials()
      upload_malicious_extension()
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"extension": "malicious_extension"}' https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisherName}/extensions/{extensionName}/versions/{version}`
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/malicious/extension |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
      meta:
        description = "Malicious Nx Console extension"
        author = "Blue Team"
      strings:
        $a = "malicious_extension"
      condition:
        $a
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=vscode_extension_installation | search "malicious_extension"
    
    ```
* **緩解措施**: 除了更新 Nx Console 擴充功能到最新版本之外，還可以設定 Visual Studio Code 的安全設定，例如啟用擴充功能的驗證和簽名。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈中有一個環節被攻擊，從而影響到整個供應鏈。技術上是指攻擊者利用供應鏈中的弱點來竊取敏感信息或進行惡意活動。
* **Malicious Extension (惡意擴充功能)**: 惡意擴充功能是指那些被設計用來竊取使用者敏感信息或進行惡意活動的擴充功能。
* **Credential Theft (憑證竊取)**: 攻擊者竊取使用者憑證和秘密，從而獲得未經授權的存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/github-links-repo-breach-to-tanstack-npm-supply-chain-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


