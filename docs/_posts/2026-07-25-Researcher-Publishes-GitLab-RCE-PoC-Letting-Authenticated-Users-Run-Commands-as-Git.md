---
layout: post
title:  "Researcher Publishes GitLab RCE PoC Letting Authenticated Users Run Commands as Git"
date:   2026-07-25 13:07:53 +0000
categories: [security]
severity: critical
---

# 🚨 GitLab 遠程命令執行漏洞解析與防禦

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Command Execution)
> * **關鍵技術**: Heap Spraying, Deserialization, JSON Parser Vulnerability

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitLab 的 Oj JSON 解析器中存在兩個記憶體腐壞漏洞，分別是堆疊緩衝區溢位和物件鍵截斷。這些漏洞允許攻擊者在 GitLab 的 Puma 工作進程中執行任意命令。
* **攻擊流程圖解**:
  1. 攻擊者提交一個精心設計的 Jupyter Notebook 到 GitLab。
  2. GitLab 的 Notebook 渲染器（ipynbdiff）將 Notebook 轉換為 JSON 格式，並使用 Oj 解析器進行解析。
  3. Oj 解析器中的漏洞被觸發，導致記憶體腐壞和任意命令執行。
* **受影響元件**: GitLab CE/EE 15.2.0 至 18.10.7、18.11.0 至 18.11.4、19.0.0 至 19.0.1，以及 Oj gem 3.13.0 至 3.17.1。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 GitLab 帳戶和提交 Notebook 的權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    notebook = {
        'cells': [
            {
                'cell_type': 'code',
                'metadata': {},
                'source': ['import os; os.system("echo Hello World!")']
            }
        ]
    }
    
    ```
* **繞過技術**: 攻擊者可以使用 Heap Spraying 技術來繞過記憶體保護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/notebook.ipynb |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GitLab_RCE {
        meta:
            description = "GitLab RCE Detection Rule"
            author = "Your Name"
        strings:
            $notebook = "notebook.ipynb"
            $payload = "import os; os.system"
        condition:
            $notebook and $payload
    }
    
    ```
* **緩解措施**: 更新 GitLab 至最新版本（18.10.8、18.11.5 或 19.0.2），並設定適當的安全配置。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 一種記憶體攻擊技術，通過在堆疊中分配大量的記憶體空間來繞過記憶體保護機制。
* **Deserialization**: 將序列化的數據轉換回原始的物件或結構。
* **JSON Parser Vulnerability**: JSON 解析器中的漏洞，允許攻擊者執行任意命令或訪問敏感數據。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


