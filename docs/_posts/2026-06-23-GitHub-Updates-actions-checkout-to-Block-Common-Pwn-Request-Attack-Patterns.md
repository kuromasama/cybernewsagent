---
layout: post
title:  "GitHub Updates actions/checkout to Block Common Pwn Request Attack Patterns"
date:   2026-06-23 14:33:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 GitHub Actions 中的 pwn request 攻擊與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `GitHub Actions`, `pull_request_target`, `actions/checkout`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub Actions 中的 `pull_request_target` 觸發器可以讓攻擊者提交惡意代碼，然後在目標倉庫中執行，從而導致 RCE。
* **攻擊流程圖解**: 
    1. 攻擊者提交一個包含惡意代碼的 pull request。
    2. `pull_request_target` 觸發器被觸發，執行相關的 workflow。
    3. `actions/checkout` 動作被使用，下載並執行惡意代碼。
* **受影響元件**: GitHub Actions 中的 `actions/checkout` 動作，特別是版本 v7。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 GitHub 帳戶，並且可以提交 pull request。
* **Payload 建構邏輯**:

    ```
    
    python
        # 惡意代碼範例
        import os
        os.system("echo 'Hello, World!' > /tmp/hello.txt")
    
    ```
    *範例指令*:

```

bash
    curl -X POST \
    https://api.github.com/repos/{owner}/{repo}/pulls \
    -H 'Authorization: Bearer {token}' \
    -H 'Content-Type: application/json' \
    -d '{"title": "Malicious PR", "body": "This is a malicious PR", "head": "malicious-branch", "base": "main"}'

```
* **繞過技術**: 攻擊者可以嘗試使用不同的提交方式，例如使用 `git` 或 `GitHub CLI`。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | /tmp/hello.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule malicious_pr {
            meta:
                description = "Detects malicious PRs"
                author = "Your Name"
            strings:
                $pr_title = "Malicious PR"
                $pr_body = "This is a malicious PR"
            condition:
                $pr_title and $pr_body
        }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
        index=github_events 
    
    | search event_type="pull_request"
    | where title="Malicious PR" and body="This is a malicious PR"
    ```
* **緩解措施**: 
    1. 更新 `actions/checkout` 動作到版本 v7 或以上。
    2. 啟用 `allow-unsafe-pr-checkout` 旗標，並設定為 `false`。
    3. 限制 workflow 的權限，避免執行惡意代碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: GitHub 提供的一種自動化工作流程工具，允許用戶定義和執行自動化任務。
* **pull_request_target**: GitHub Actions 中的一種觸發器，當 pull request 被提交或更新時觸發。
* **actions/checkout**: GitHub Actions 中的一種動作，下載並執行指定的代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/github-updates-actionscheckout-to-block.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


