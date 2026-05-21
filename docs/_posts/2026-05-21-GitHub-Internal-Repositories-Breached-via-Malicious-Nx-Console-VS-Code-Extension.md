---
layout: post
title:  "GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension"
date:   2026-05-21 09:26:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GitHub 內部儲存庫遭駭事件：供應鏈攻擊的新挑戰

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Supply Chain Attack, Trojanized Extension, Credential Stealer

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Nx Console Microsoft Visual Studio Code (VS Code) 擴充功能被駭客竄改，導致 GitHub 內部儲存庫遭駭。
* **攻擊流程圖解**:
  1.駭客竄改 Nx Console 擴充功能，加入 credential stealer。
  2.駭客將竄改的擴充功能上傳到 Visual Studio Marketplace。
  3.開發人員安裝竄改的擴充功能。
  4.駭客透過竄改的擴充功能竊取開發人員的認證資料。
  5.駭客使用竊取的認證資料登入 GitHub，進而存取內部儲存庫。
* **受影響元件**: Nx Console Microsoft Visual Studio Code (VS Code) 擴充功能，GitHub 內部儲存庫。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客需要有能力竄改 Nx Console 擴充功能，並將其上傳到 Visual Studio Marketplace。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 payload
    import requests
    
    def steal_credentials():
        # 竊取開發人員的認證資料
        credentials = requests.get('https://example.com/credentials').json()
        return credentials
    
    def upload_payload():
        # 上傳竄改的擴充功能到 Visual Studio Marketplace
        payload = {'extension': 'nx-console', 'version': '1.0.0'}
        response = requests.post('https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisherName}/extensions/{extensionName}/versions/{version}', json=payload)
        return response.json()
    
    # 執行 payload
    credentials = steal_credentials()
    upload_payload()
    
    ```
* **繞過技術**: 駭客可以使用各種技術來繞過安全防護，例如使用加密或隱藏 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/malware |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule nx_console_malware {
        meta:
            description = "Detects nx-console malware"
            author = "Your Name"
        strings:
            $a = "nx-console" ascii
            $b = "malware" ascii
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 Nx Console 擴充功能到最新版本，使用安全的認證資料存儲，監控系統日誌以偵測可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 一種攻擊方式，駭客透過竄改軟體供應鏈中的某個環節，進而影響最終使用者的安全。
* **Trojanized Extension (竄改的擴充功能)**: 一種竄改的軟體擴充功能，通常包含惡意代碼，駭客可以透過這種方式竊取使用者的認證資料或進行其他惡意活動。
* **Credential Stealer (認證資料竊取工具)**: 一種工具，駭客可以使用它來竊取使用者的認證資料，例如密碼或 API 金鑰。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/github-internal-repositories-breached.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


