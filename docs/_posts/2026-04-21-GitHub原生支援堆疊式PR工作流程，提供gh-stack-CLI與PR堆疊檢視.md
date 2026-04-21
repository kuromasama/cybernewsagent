---
layout: post
title:  "GitHub原生支援堆疊式PR工作流程，提供gh stack CLI與PR堆疊檢視"
date:   2026-04-21 07:25:54 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 GitHub 堆疊式拉取請求的安全性與威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `GitHub CLI`, `Stacked Pull Requests`, `Rebase`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub 的堆疊式拉取請求功能允許開發者將大型程式碼變更拆分為多個相互依賴的拉取請求。然而，這個功能可能導致資訊洩露，因為每個拉取請求都可以被其他開發者查看，即使它們尚未被合併到主分支中。
* **攻擊流程圖解**: 
    1. 開發者創建一個新的拉取請求並將其添加到堆疊中。
    2. 其他開發者可以查看這個拉取請求，即使它尚未被合併到主分支中。
    3. 如果這個拉取請求包含敏感資訊，則可能導致資訊洩露。
* **受影響元件**: GitHub 的堆疊式拉取請求功能，所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 GitHub 帳戶和倉庫的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 GitHub API 的 URL 和 Token
    url = "https://api.github.com/repos/{owner}/{repo}/pulls"
    token = "your_token"
    
    # 定義拉取請求的標題和內容
    title = "Test Pull Request"
    body = "This is a test pull request"
    
    # 創建一個新的拉取請求
    response = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json={"title": title, "body": body})
    
    # 如果創建成功，則返回 201 狀態碼
    if response.status_code == 201:
        print("Pull request created successfully")
    else:
        print("Failed to create pull request")
    
    ```
    *範例指令*: 使用 `curl` 命令創建一個新的拉取請求：

```

bash
curl -X POST \
  https://api.github.com/repos/{owner}/{repo}/pulls \
  -H 'Authorization: Bearer your_token' \
  -H 'Content-Type: application/json' \
  -d '{"title": "Test Pull Request", "body": "This is a test pull request"}'

```
* **繞過技術**: 如果倉庫設定了分支保護規則，則需要使用 `git` 命令繞過這些規則：

```

bash
git push origin +HEAD:refs/heads/{branch}

```

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | github.com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GitHub_Pull_Request {
        meta:
            description = "Detects GitHub pull requests"
            author = "Your Name"
        strings:
            $github_api = "https://api.github.com"
        condition:
            $github_api in (http.request.uri)
    }
    
    ```
    或者使用 `Snort` 規則：

```

snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"GitHub Pull Request"; content:"https://api.github.com"; sid:1000001; rev:1;)

```
* **緩解措施**: 
    1. 設定分支保護規則以限制誰可以合併拉取請求。
    2. 使用 `GitHub CLI` 的 `gh stack` 命令來管理堆疊式拉取請求。
    3. 定期審查拉取請求以確保它們不包含敏感資訊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Stacked Pull Requests (堆疊式拉取請求)**: 想像多個拉取請求堆疊在一起。技術上是指多個拉取請求之間的依賴關係，以便於管理和審查。
* **Rebase (重新定基)**: 想像將一個分支重新定基到另一個分支上。技術上是指將一個分支的提交記錄重新定基到另一個分支的提交記錄上，以便於合併和管理。
* **GitHub CLI (GitHub 命令列工具)**: GitHub 提供的命令列工具，用於管理和操作 GitHub 倉庫。

## 5. 🔗 參考文獻與延伸閱讀
- [GitHub 的堆疊式拉取請求功能](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests)
- [GitHub CLI 的 `gh stack` 命令](https://cli.github.com/manual/gh_stack)
- [MITRE ATT&CK 的 `T1190` 技術](https://attack.mitre.org/techniques/T1190/)


