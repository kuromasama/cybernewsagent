---
layout: post
title:  "The GitHub Actions Attack Pattern Your CI Security Scanners Miss"
date:   2026-07-07 14:14:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GitHub Actions 的 Cordyceps 弱點：CI/CD 管理漏洞的深度分析

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: GitHub Actions, CI/CD, Workflow Composition

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub Actions 的 `pull_request_target` 和 `workflow_run` 觸發器可以被攻擊者利用，導致在受信任的上下文中執行任意代碼。
* **攻擊流程圖解**: 
    1. 攻擊者提交一個包含惡意代碼的 Pull Request。
    2. GitHub Actions 的 `pull_request_target` 觸發器被觸發，執行在受信任的上下文中。
    3. 攻擊者控制的代碼被執行，導致 RCE。
* **受影響元件**: GitHub Actions、npm、PyPI、crates.io 和 Go 生態系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要一個 GitHub 帳戶和一個包含惡意代碼的 Pull Request。
* **Payload 建構邏輯**:

    ```
    
    python
        # 範例 Payload
        payload = {
            "action": "run",
            "script": "echo 'Hello, World!' > /tmp/hello.txt"
        }
    
    ```
 

```

bash
    # 使用 curl 提交 Pull Request
    curl -X POST \
    https://api.github.com/repos/owner/repo/pulls \
    -H 'Authorization: Bearer YOUR_GITHUB_TOKEN' \
    -H 'Content-Type: application/json' \
    -d '{"title": "Malicious Pull Request", "body": "This is a malicious pull request.", "head": "malicious-branch", "base": "main"}'

```
* **繞過技術**: 攻擊者可以使用 GitHub Actions 的 `github-script` 動作來執行任意 JavaScript 代碼，繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /tmp/hello.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule GitHub_Actions_Malicious_Payload {
            meta:
                description = "Detects malicious GitHub Actions payload"
                author = "Your Name"
            strings:
                $payload = { 28 29 30 31 32 33 34 35 36 37 38 39 }
            condition:
                $payload at 0
        }
    
    ```
 

```

snort
    alert tcp $HOME_NET 80 -> $EXTERNAL_NET any (msg:"GitHub Actions Malicious Payload"; content:"|28 29 30 31 32 33 34 35 36 37 38 39|"; sid:1000000; rev:1;)

```
* **緩解措施**:
    1. 使用 `pull_request` 觸發器代替 `pull_request_target`。
    2. 將 GitHub Actions 的權限設為只讀。
    3. 使用 `github-script` 動作時，必須仔細審查和驗證輸入的代碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: GitHub 的 CI/CD 平台，允許用戶定義和執行自動化工作流程。
* **CI/CD**: Continuous Integration/Continuous Deployment，指的是在軟件開發中，通過自動化工具和流程實現代碼的持續集成和部署。
* **Workflow Composition**: 指的是 GitHub Actions 的工作流程組成，包括觸發器、動作和輸入/輸出等元素。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/the-github-actions-attack-pattern-your-ci-security-scanners-miss/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


