---
layout: post
title:  "供應鏈安全框架SLSA解析Mini Shai-Hulud事件，驗證NPM套件安全不能只看簽章"
date:   2026-06-15 03:27:43 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Mini Shai-Hulud NPM 供應鏈攻擊：SLSA 的局限性與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Cache Poisoning, OIDC Token Extraction, SLSA (Supply-chain Levels for Software Artifacts)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Mini Shai-Hulud 攻擊利用 GitHub Actions 工作流程設定缺陷，結合快取污染（Cache Poisoning）與 OIDC 權杖擷取（OIDC Token Extraction）手法，透過合法 CI/CD 管線發布惡意 NPM 套件。
* **攻擊流程圖解**:
  1. 攻擊者利用 GitHub Actions 工作流程設定缺陷，取得 OIDC 權杖。
  2. 攻擊者使用 OIDC 權杖，透過 Sigstore 與 NPM 可信發布機制（Trusted Publishing）完成簽署。
  3. 惡意套件的來源證明（Provenance Attestation）仍指向正確的儲存庫、工作流程與程式碼分支。
* **受影響元件**: NPM 套件、GitHub Actions、Sigstore

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: GitHub Actions 工作流程設定缺陷、OIDC 權杖
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 取得 OIDC 權杖
    oidc_token = requests.get('https://github.com/login/oauth/access_token', params={
        'client_id': 'your_client_id',
        'client_secret': 'your_client_secret',
        'code': 'your_code'
    }).json()['access_token']
    
    # 使用 OIDC 權杖簽署惡意套件
    signed_package = requests.post('https://sigstore.dev/api/v1/sign', headers={
        'Authorization': f'Bearer {oidc_token}'
    }, json={
        'package': 'your_package_name',
        'version': 'your_package_version'
    }).json()
    
    # 發布惡意套件
    requests.post('https://registry.npmjs.org/-/npm/v1/packages/your_package_name', headers={
        'Authorization': f'Bearer {oidc_token}'
    }, json=signed_package)
    
    ```
* **繞過技術**: 使用合法的 OIDC 權杖與 Sigstore 簽署機制，繞過傳統的安全檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /path/to/malicious/package |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_package {
        meta:
            description = "Detects malicious packages signed with stolen OIDC tokens"
            author = "Your Name"
        strings:
            $oidc_token = "your_oidc_token"
        condition:
            $oidc_token in (pe.imports[0].name or pe.imports[1].name)
    }
    
    ```
* **緩解措施**:
  1. 更新 GitHub Actions 工作流程設定，修復設定缺陷。
  2. 啟用 Sigstore 的安全檢查，驗證 OIDC 權杖的合法性。
  3. 監控 NPM 套件的發布，偵測惡意套件的發布。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SLSA (Supply-chain Levels for Software Artifacts)**: 一個供應鏈安全框架，協助開發者與企業判斷軟體成品是否來自可信流程。
* **OIDC (OpenID Connect)**: 一個身份驗證協議，允許用戶在不同應用程序之間共享身份信息。
* **Sigstore**: 一個簽署機制，允許開發者簽署軟體成品，驗證其來源與完整性。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176596)
- [SLSA 官方網站](https://slsa.dev/)
- [Sigstore 官方網站](https://sigstore.dev/)


