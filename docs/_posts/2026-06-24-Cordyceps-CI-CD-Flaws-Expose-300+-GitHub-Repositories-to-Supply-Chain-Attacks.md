---
layout: post
title:  "Cordyceps CI/CD Flaws Expose 300+ GitHub Repositories to Supply-Chain Attacks"
date:   2026-06-24 14:12:04 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CI/CD 工作流弱點：Cordyceps 攻擊技術分析

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `CI/CD Workflow`, `Unauthenticated Access`, `Supply Chain Attack`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CI/CD 工作流配置弱點，允許未經驗證的用戶提交 pull request，並觸發特權工作流，導致命令執行、權限提升和供應鏈攻擊。
* **攻擊流程圖解**:
  1. 未經驗證的用戶提交 pull request
  2. CI/CD 工作流觸發特權工作流
  3. 工作流執行命令，導致命令執行、權限提升和供應鏈攻擊
* **受影響元件**: GitHub、Azure DevOps、GitLab 等 CI/CD 平台

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 未經驗證的用戶帳戶
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 提交 pull request
    url = "https://api.github.com/repos/{owner}/{repo}/pulls"
    data = {
        "title": "Malicious Pull Request",
        "body": "This is a malicious pull request",
        "head": "malicious-branch",
        "base": "main"
    }
    response = requests.post(url, json=data)
    
    # 觸發 CI/CD 工作流
    url = "https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
    data = {
        "ref": "main",
        "inputs": {
            "malicious-input": "malicious-value"
        }
    }
    response = requests.post(url, json=data)
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 payload

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `malicious-hash` | `192.168.1.100` | `malicious-domain.com` | `/malicious/file/path` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_pull_request {
      meta:
        description = "Detects malicious pull requests"
      strings:
        $malicious_title = "Malicious Pull Request"
        $malicious_body = "This is a malicious pull request"
      condition:
        $malicious_title and $malicious_body
    }
    
    ```
* **緩解措施**: 更新 CI/CD 工作流配置，限制未經驗證的用戶提交 pull request，並啟用 WAF 和 EDR

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **CI/CD (Continuous Integration/Continuous Deployment)**: 一種軟件開發方法，旨在自動化軟件的構建、測試和部署過程。
* **Supply Chain Attack (供應鏈攻擊)**: 一種攻擊方式，目的是攻擊軟件供應鏈中的弱點，從而影響最終用戶。
* **WAF (Web Application Firewall)**: 一種網絡安全系統，旨在保護網絡應用程式免受攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


