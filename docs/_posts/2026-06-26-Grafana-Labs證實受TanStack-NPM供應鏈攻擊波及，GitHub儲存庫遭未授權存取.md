---
layout: post
title:  "Grafana Labs證實受TanStack NPM供應鏈攻擊波及，GitHub儲存庫遭未授權存取"
date:   2026-06-26 02:42:19 +0000
categories: [security]
severity: high
---

# 🔥 解析 GitHub 供應鏈攻擊：Grafana Labs 資安事件剖析
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `GitHub Actions`, `Token Broker`, `CI/CD`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Grafana Labs 的 GitHub 自架 runner 執行惡意程式碼，造成部分憑證外洩。攻擊者利用漏洞下載了 GitHub 儲存庫，包括公開與私有原始碼，以及部分團隊存放內部營運資訊的儲存庫。
* **攻擊流程圖解**: 
    1. 攻擊者獲得 GitHub runner 的存取權限。
    2. 攻擊者執行惡意程式碼，導致憑證外洩。
    3. 攻擊者利用外洩的憑證下載 GitHub 儲存庫。
* **受影響元件**: Grafana Labs 的 GitHub 自架 runner 和相關儲存庫。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 GitHub runner 的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 GitHub API 的 URL 和 Token
    url = "https://api.github.com/repos/{owner}/{repo}/actions/workflows"
    token = "YOUR_GITHUB_TOKEN"
    
    # 定義惡意程式碼的內容
    payload = {
        "name": "Malicious Workflow",
        "on": {
            "push": {
                "branches": ["main"]
            }
        },
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Run Malicious Code",
                        "run": "echo 'Malicious Code Here'"
                    }
                ]
            }
        }
    }
    
    # 發送請求到 GitHub API
    response = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
    
    # 檢查請求的結果
    if response.status_code == 201:
        print("Malicious workflow created successfully!")
    else:
        print("Failed to create malicious workflow.")
    
    ```
    *範例指令*: 使用 `curl` 命令發送請求到 GitHub API。
* **繞過技術**: 攻擊者可以利用 GitHub 的 API 來繞過安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Malicious_GitHub_Workflow {
        meta:
            description = "Detects malicious GitHub workflows"
            author = "Your Name"
        strings:
            $malicious_code = "echo 'Malicious Code Here'"
        condition:
            $malicious_code
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。
* **緩解措施**: 除了更新修補之外，還可以設定 GitHub 的安全措施，例如啟用兩步 驗證、限制存取權限等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **GitHub Actions**: GitHub 的 CI/CD 工具，允許用戶定義和執行自動化工作流程。
* **Token Broker**: 一種安全的令牌管理系統，允許用戶管理和存儲敏感的令牌和憑證。
* **CI/CD**: Continuous Integration/Continuous Deployment 的縮寫，指的是持續整合和持續部署的軟件開發實踐。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176888)
- [GitHub Actions 文檔](https://docs.github.com/en/actions)
- [Token Broker 文檔](https://docs.github.com/en/actions/security-guides/token-broker)


