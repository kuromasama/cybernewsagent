---
layout: post
title:  "駭客團體TeamPCP兜售GitHub近4千個儲存庫資料，底價為5萬美元"
date:   2026-05-24 13:08:37 +0000
categories: [security]
severity: high
---

# 🔥 解析 TeamPCP 對 GitHub 的代碼竊取事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Visual Studio Code`, `Nx Console`, `GitHub`, `Supply Chain Attack`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub 員工安裝了 Nx Console 的 Visual Studio Code 延伸套件，導致內部儲存庫遭入侵。這個延伸套件可能包含惡意代碼或配置錯誤，導致駭客可以存取 GitHub 的內部儲存庫。
* **攻擊流程圖解**: 
  1. 員工安裝 Nx Console 的 Visual Studio Code 延伸套件。
  2. 延伸套件執行惡意代碼或配置錯誤，導致駭客可以存取 GitHub 的內部儲存庫。
  3. 駭客下載內部儲存庫的代碼。
* **受影響元件**: Visual Studio Code、Nx Console、GitHub。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客需要有 GitHub 員工的帳號和密碼，或者可以利用其他漏洞存取 GitHub 的內部儲存庫。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 GitHub 的 API 端點
    github_api = "https://api.github.com"
    
    # 定義內部儲存庫的名稱
    repo_name = "example/repo"
    
    # 定義下載代碼的 API 端點
    download_api = f"{github_api}/repos/{repo_name}/zipball"
    
    # 下載代碼
    response = requests.get(download_api)
    
    # 儲存代碼
    with open("repo.zip", "wb") as f:
        f.write(response.content)
    
    ```
  *範例指令*: `curl -X GET https://api.github.com/repos/example/repo/zipball -o repo.zip`
* **繞過技術**: 駭客可以利用其他漏洞或社會工程學技巧來繞過 GitHub 的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/repo |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule github_repo_download {
      meta:
        description = "Detect GitHub repository download"
        author = "Your Name"
      strings:
        $github_api = "https://api.github.com"
        $download_api = "/repos/*/zipball"
      condition:
        http.request.uri == $github_api + $download_api
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=github_logs
    
    | search "https://api.github.com/repos/*/zipball"
    | stats count as download_count by user
    | where download_count > 5
    ```
* **緩解措施**: 除了更新修補之外，還可以設定 GitHub 的安全措施，例如啟用兩步 驗證、限制存取權限等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈就像是一個長長的鏈條，攻擊者可以在任何一個環節進行攻擊。技術上是指攻擊者利用供應鏈中的弱點來攻擊目標公司。
* **Visual Studio Code (VS Code)**: 一個開源的代碼編輯器，支持多種程式語言。
* **Nx Console**: 一個開源的代碼管理工具，支持多種程式語言。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176070)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


