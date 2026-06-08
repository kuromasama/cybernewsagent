---
layout: post
title:  "Gogs patches critical zero-day enabling remote code execution"
date:   2026-06-08 20:06:01 +0000
categories: [security]
severity: critical
---

# 🚨 Gogs Argument Injection Vulnerability 解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Argument Injection, Git Repository, Rebase Merge

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Gogs 的 Merge 函數沒有正確檢查用戶輸入的參數，導致攻擊者可以注入惡意參數，從而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者創建一個新的 Git 倉庫。
  2. 攻擊者啟用 Rebase Merge 功能。
  3. 攻擊者提交一個包含惡意代碼的 Commit。
  4. Gogs 執行 Merge 函數，注入惡意參數。
  5. 惡意代碼被執行，實現遠程代碼執行。
* **受影響元件**: Gogs 0.14.2 和 0.15.0+dev 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個有效的 Gogs 用戶帳戶。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意代碼
    malicious_code = "echo 'Hello, World!' > /tmp/hello.txt"
    
    # 創建一個新的 Git 倉庫
    repo_name = "malicious-repo"
    requests.post(f"http://gogs-server/api/v1/repos", json={"name": repo_name})
    
    # 啟用 Rebase Merge 功能
    requests.patch(f"http://gogs-server/api/v1/repos/{repo_name}/settings", json={"rebase_merge": True})
    
    # 提交一個包含惡意代碼的 Commit
    commit_message = "Malicious commit"
    requests.post(f"http://gogs-server/api/v1/repos/{repo_name}/commits", json={"message": commit_message, "content": malicious_code})
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術繞過 Gogs 的安全機制，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | gogs-server.com | /tmp/hello.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Gogs_Argument_Injection {
      meta:
        description = "Gogs Argument Injection Vulnerability"
        author = "Your Name"
      strings:
        $malicious_code = "echo 'Hello, World!' > /tmp/hello.txt"
      condition:
        $malicious_code in (pe.data or pe.sections[0].data)
    }
    
    ```
* **緩解措施**: 更新 Gogs 至最新版本，禁用 Rebase Merge 功能，限制用戶權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Argument Injection (參數注入)**: 想像一個函數需要多個參數，但是攻擊者可以注入惡意參數，從而實現惡意功能。技術上是指攻擊者可以注入惡意參數，從而實現遠程代碼執行。
* **Rebase Merge (重新基礎合併)**: Git 的一個功能，允許用戶重新基礎合併分支。技術上是指用戶可以重新基礎合併分支，從而實現遠程代碼執行。
* **Git Repository (Git 倉庫)**: Git 的一個儲存庫，允許用戶儲存和管理代碼。技術上是指 Git 的一個儲存庫，允許用戶儲存和管理代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/gogs-patches-critical-zero-day-enabling-remote-code-execution/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


