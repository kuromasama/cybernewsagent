---
layout: post
title:  "Shai Hulud attack ships signed malicious TanStack, Mistral npm packages"
date:   2026-05-12 14:04:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Shai-Hulud 供應鏈攻擊：利用 OpenID Connect 權杖劫持與 Malicious Package 分佈

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: OpenID Connect 權杖劫持、Malicious Package 分佈、GitHub Actions Cache Poisoning

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 OpenID Connect 權杖劫持，取得 TanStack 和 Mistral AI 專案的合法存取權，進而發佈惡意的 Package 版本。
* **攻擊流程圖解**:
  1. 攻擊者取得 TanStack 或 Mistral AI 專案的 OpenID Connect 權杖。
  2. 攻擊者使用劫持的權杖，發佈惡意的 Package 版本至 npm 或 PyPI。
  3. 使用者安裝惡意的 Package 版本，導致攻擊者取得使用者的敏感資訊。
* **受影響元件**: TanStack、Mistral AI、Guardrails AI、UiPath、OpenSearch 等專案。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得 TanStack 或 Mistral AI 專案的 OpenID Connect 權杖。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意的 Package 版本
    malicious_package = {
        "name": "tanstack/router",
        "version": "1.2.3",
        "description": "Malicious package"
    }
    
    # 使用劫持的權杖，發佈惡意的 Package 版本
    response = requests.post(
        "https://registry.npmjs.org/-/npm/v1/packages",
        json=malicious_package,
        headers={"Authorization": "Bearer <token>"}
    )
    
    print(response.json())
    
    ```
* **繞過技術**: 攻擊者可以使用 GitHub Actions Cache Poisoning，繞過安全檢查，發佈惡意的 Package 版本。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| <hash> | <ip> | <domain> | <file_path> |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
      meta:
        description = "Malicious package detection"
        author = "Your Name"
      strings:
        $malicious_package = "tanstack/router" wide
      condition:
        $malicious_package
    }
    
    ```
* **緩解措施**: 使用者應該更新至最新的 Package 版本，並檢查是否有任何惡意的 Package 版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OpenID Connect (OIDC)**: 一種身份驗證協議，允許使用者使用單一帳戶，存取多個應用程式。
* **GitHub Actions**: 一種持續整合與持續部署 (CI/CD) 工具，允許使用者自動化軟體開發流程。
* **Malicious Package**: 惡意的 Package 版本，可能包含惡意程式碼或資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


