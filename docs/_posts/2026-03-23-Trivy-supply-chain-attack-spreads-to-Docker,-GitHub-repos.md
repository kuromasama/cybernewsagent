---
layout: post
title:  "Trivy supply-chain attack spreads to Docker, GitHub repos"
date:   2026-03-23 18:43:18 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamPCP 對 Trivy 的供應鏈攻擊：利用 GitHub 令牌劫持和 Docker Hub 欺騙
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak 和 RCE (Remote Code Execution)
> * **關鍵技術**: GitHub 令牌劫持、Docker Hub 欺騙、Supply Chain Attack

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TeamPCP 攻擊者利用了 Aqua Security 的 GitHub 令牌管理不善，獲得了對 aquasec-com GitHub 組織的存取權限，進而修改了 Trivy 的代碼並發布了惡意版本。
* **攻擊流程圖解**:
  1. 攻擊者獲得 Aqua Security 的 GitHub 令牌。
  2. 攻擊者使用獲得的令牌存取 aquasec-com GitHub 組織。
  3. 攻擊者修改 Trivy 的代碼，添加了資訊竊取功能。
  4. 攻擊者發布了惡意版本的 Trivy 到 Docker Hub。
* **受影響元件**: Trivy 0.69.5 和 0.69.6 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Aqua Security 的 GitHub 令牌。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import requests
    
      # GitHub 令牌
      token = "your_token_here"
    
      # aquasec-com GitHub 組織
      org = "aquasec-com"
    
      # Trivy 代碼庫
      repo = "trivy"
    
      # 修改 Trivy 代碼
      payload = {
        "action": "update",
        "repo": repo,
        "org": org,
        "token": token
      }
    
      # 發布惡意版本
      response = requests.post("https://api.github.com/repos/{org}/{repo}/releases".format(org=org, repo=repo), json=payload)
    
    ```
* **繞過技術**: 攻擊者可以使用 GitHub 令牌劫持和 Docker Hub 欺騙來繞過安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Trivy_Malicious_Release {
        meta:
          description = "Trivy 惡意版本偵測"
          author = "Your Name"
        strings:
          $a = "Trivy" wide
          $b = "malicious" wide
        condition:
          $a and $b
      }
    
    ```
* **緩解措施**: 更新 Trivy 到最新版本，使用安全的 GitHub 令牌管理，監控 Docker Hub 上的發布。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，如同一條長長的鏈子，攻擊者可以在任意一環上發動攻擊，從而影響整個供應鏈。技術上是指攻擊者針對軟件供應鏈中的弱點，例如第三方庫或開源軟件，從而影響最終使用者的安全。
* **GitHub 令牌劫持 (GitHub Token Hijacking)**: 攻擊者竊取或劫持 GitHub 用戶的令牌，從而獲得對用戶 GitHub 資源的存取權限。
* **Docker Hub 欺騙 (Docker Hub Spoofing)**: 攻擊者偽造或修改 Docker Hub 上的發布，從而欺騙用戶下載惡意軟件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/trivy-supply-chain-attack-spreads-to-docker-github-repos/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


