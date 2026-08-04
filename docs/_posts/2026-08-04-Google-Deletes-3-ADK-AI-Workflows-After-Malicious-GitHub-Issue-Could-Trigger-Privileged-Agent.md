---
layout: post
title:  "Google Deletes 3 ADK AI Workflows After Malicious GitHub Issue Could Trigger Privileged Agent"
date:   2026-08-04 13:54:16 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google ADK AI 工作流漏洞：利用與防禦繞過

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程命令執行 (RCE)
> * **關鍵技術**: Prompt Injection, 代理人身份驗證繞過, Git Hook

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google ADK AI 工作流中的 `issue-analyze.yml` 和 `issue-fix.yml` 文件存在安全漏洞，允許攻擊者通過 Prompt Injection 繞過代理人身份驗證，進而執行任意命令。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 GitHub 問題，並在評論中包含 `/adk-issue-fix` 命令。
  2. `issue-analyze.yml` 工作流自動運行，使用 `ADK_GCP_SA_KEY` 認證，然後將生成的分析結果作為評論發布。
  3. `issue-fix.yml` 工作流監聽 `/adk-issue-fix` 評論，並限制執行權限為所有者、成員或協作者。
  4. 攻擊者通過 Prompt Injection 繞過代理人身份驗證，進而執行 `issue-fix.yml` 工作流。
* **受影響元件**: Google ADK AI 工作流，特別是 `issue-analyze.yml` 和 `issue-fix.yml` 文件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個 GitHub 問題，並在評論中包含 `/adk-issue-fix` 命令。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 創建 GitHub 問題
    url = "https://api.github.com/repos/{owner}/{repo}/issues"
    data = {"title": "Test Issue", "body": "/adk-issue-fix"}
    response = requests.post(url, json=data)
    
    # 獲取問題 ID
    issue_id = response.json()["id"]
    
    # 發布評論
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_id}/comments"
    data = {"body": "Test Comment"}
    response = requests.post(url, json=data)
    
    ```
* **繞過技術**: 攻擊者可以通過 Prompt Injection 繞過代理人身份驗證，進而執行 `issue-fix.yml` 工作流。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | github.com | `issue-analyze.yml` |
|  |  | github.com | `issue-fix.yml` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule github_adk_ai_workflow {
      meta:
        description = "Detects GitHub ADK AI workflow exploitation"
      strings:
        $a = "/adk-issue-fix"
      condition:
        $a in (all of them)
    }
    
    ```
* **緩解措施**: 更新 Google ADK AI 工作流，特別是 `issue-analyze.yml` 和 `issue-fix.yml` 文件，限制執行權限為所有者、成員或協作者，並實施安全的 Prompt Injection 防禦機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Prompt Injection**: 一種攻擊技術，通過注入特定的輸入，繞過安全機制，進而執行任意命令。
* **代理人身份驗證繞過**: 一種攻擊技術，通過繞過代理人身份驗證，進而執行任意命令。
* **Git Hook**: 一種 Git 功能，允許在 Git 操作中執行任意命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/google-deletes-3-adk-ai-workflows-after.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


