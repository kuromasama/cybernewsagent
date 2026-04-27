---
layout: post
title:  "PyPI package with 1.1M monthly downloads hacked to push infostealer"
date:   2026-04-27 19:09:21 +0000
categories: [security]
severity: critical
---

# 🚨 PyPI 套件劫持解析：利用 GitHub Actions 脆弱性進行惡意軟體分發

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: GitHub Actions 脆弱性、Shell Code 注入、Malicious Package 分發

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub Actions 脆弱性允許攻擊者注入 Shell Code，從而控制工作流程並發布惡意軟體。
* **攻擊流程圖解**:
  1. 攻擊者發布惡意評論到 Pull Request 中。
  2. GitHub Actions 脆弱性被利用，注入 Shell Code。
  3. Shell Code 執行，控制工作流程。
  4. 工作流程發布惡意軟體到 PyPI 和 Docker Hub。
* **受影響元件**: elementary-data 套件 (版本 0.23.3) 和 Docker Image (標籤 0.23.3 和 latest)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: GitHub 帳戶和 elementary-data 套件的 Pull Request 權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意評論內容
      comment = "Malicious comment with shell code injection"
      # Shell Code 注入
      shell_code = "echo 'Malicious shell code' > malicious.sh"
      # 發布惡意軟體
      package_name = "elementary-data"
      version = "0.23.3"
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"comment": "' + comment + '"}' https://api.github.com/repos/elementary-data/elementary-data/pulls/1/comments`
* **繞過技術**: 利用 GitHub Actions 脆弱性注入 Shell Code，從而控制工作流程。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious.sh |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule MaliciousPackage {
        meta:
          description = "Detects malicious package"
        strings:
          $a = "malicious.sh"
        condition:
          $a
      }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)： `index=github_actions sourcetype=github_comment comment="Malicious comment with shell code injection"`
* **緩解措施**: 更新 elementary-data 套件到版本 0.23.4 或以上，刪除惡意軟體和 Docker Image。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: 一種自動化工作流程工具，允許開發者自動化軟體開發和部署過程。
* **Shell Code 注入**: 一種攻擊技術，注入惡意 Shell Code 到系統中，從而控制系統。
* **Malicious Package**: 惡意軟體套件，包含惡意代碼，可能會造成系統損害。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/pypi-package-with-11m-monthly-downloads-hacked-to-push-infostealer/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


