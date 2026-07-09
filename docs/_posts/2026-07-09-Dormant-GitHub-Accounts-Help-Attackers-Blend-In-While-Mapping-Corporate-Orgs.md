---
layout: post
title:  "Dormant GitHub Accounts Help Attackers Blend In While Mapping Corporate Orgs"
date:   2026-07-09 19:26:57 +0000
categories: [security]
severity: high
---

# 🔥 解析 GitHub API 枚舉攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: API 枚舉、OAuth Token 繞過、GraphQL 查詢

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: GitHub API 的設計允許未經驗證的請求存取公共資料，攻擊者利用此特性進行枚舉攻擊。
* **攻擊流程圖解**:
  1. 攻擊者創建或取得「鬼」帳戶（Ghost Account），這些帳戶通常是幾年前創建的，長時間不活躍。
  2. 攻擊者使用這些帳戶通過 GitHub API 發送請求，枚舉目標組織的公共倉庫、用戶關注者、Gist 等資訊。
  3. 攻擊者可能使用 GraphQL 查詢進一步收集資訊。
* **受影響元件**: GitHub API、OAuth Token、個人存取令牌（PAT）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要取得 GitHub 帳戶（尤其是「鬼」帳戶）和 OAuth Token 或 PAT。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 使用 GraphQL 查詢枚舉組織的公共倉庫
    query = """
      query {
        organization(login: "example-org") {
          repositories(first: 100) {
            edges {
              node {
                name
              }
            }
          }
        }
      }
    """
    
    response = requests.post('https://api.github.com/graphql', json={'query': query})
    print(response.json())
    
    ```
  *範例指令*: 使用 `curl` 發送 GraphQL 查詢請求。
* **繞過技術**: 攻擊者可能使用合法的 OAuth Token 或 PAT 繞過驗證機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 192.0.2.1 |
| Domain | example.com |
| File Path | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule github_enum {
      meta:
        description = "GitHub 枚舉攻擊"
        author = "Your Name"
      strings:
        $graphql_query = "query { organization"
      condition:
        $graphql_query
    }
    
    ```
  或者是使用 Splunk 查詢語法進行偵測。
* **緩解措施**: 
  1. 監控 GitHub API 請求，特別是來自不活躍帳戶的請求。
  2. 限制 OAuth Token 和 PAT 的使用。
  3. 啟用 GitHub 的安全功能，例如兩步 驗證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **GraphQL**: 一種查詢語言，允許用戶定義所需的資料結構。
* **OAuth Token**: 一種用於授權的令牌，允許應用程序代表用戶進行操作。
* **個人存取令牌 (PAT)**: 一種用於授權的令牌，允許用戶代表自己進行操作。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://thehackernews.com/2026/07/dormant-github-accounts-help-attackers.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1082/)


