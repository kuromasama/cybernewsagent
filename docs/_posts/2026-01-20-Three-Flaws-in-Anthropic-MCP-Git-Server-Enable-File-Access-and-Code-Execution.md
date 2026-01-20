---
layout: post
title:  "Three Flaws in Anthropic MCP Git Server Enable File Access and Code Execution"
date:   2026-01-20 18:27:27 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Anthropic MCP Git 伺服器的三個安全漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：8.8 [v3] / 6.5 [v4])
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Path Traversal, Argument Injection, Prompt Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 
    + CVE-2025-68143：`git_init` 工具接受任意檔案系統路徑而未進行驗證，導致路徑遍歷漏洞。
    + CVE-2025-68144：`git_diff` 和 `git_checkout` 函數直接傳遞使用者控制的引數給 Git CLI 命令而未進行過濾，導致引數注入漏洞。
    + CVE-2025-68145：缺乏路徑驗證當使用 `--repository` 旗標限制操作到特定儲存庫路徑，導致路徑遍歷漏洞。
* **攻擊流程圖解**:
    1. 攻擊者影響 AI 助手讀取的內容（例如：惡意的 README、有毒的問題描述、受損的網頁）。
    2. 利用漏洞創建一個 Git 儲存庫。
    3. 寫入一個惡意的 `.git/config` 檔案。
    4. 寫入一個 `.gitattributes` 檔案以套用過濾器到特定檔案。
    5. 寫入一個 shell 腳本包含有效載荷。
    6. 寫入一個檔案觸發過濾器。
    7. 呼叫 `git_add` 執行過濾器，從而執行有效載荷。
* **受影響元件**: 
    + mcp-server-git (版本 < 2025.9.25 和 < 2025.12.18)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 
    + 能夠影響 AI 助手讀取的內容。
    + 網路位置：能夠存取 mcp-server-git 伺服器。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    payload = {
        "repository": "/path/to/vulnerable/repository",
        "file": ".git/config",
        "content": "[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\nignorecase = true\nprecomposeunicode = true\n[remote \"origin\"]\nurl = https://example.com/repo.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\nremote = origin\nmerge = refs/heads/master"
    }
    
    ```
 

```

bash
# 範例指令
curl -X POST \
  http://example.com/mcp-server-git \
  -H 'Content-Type: application/json' \
  -d '{"repository": "/path/to/vulnerable/repository", "file": ".git/config", "content": "[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\nignorecase = true\nprecomposeunicode = true\n[remote \"origin\"]\nurl = https://example.com/repo.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\nremote = origin\nmerge = refs/heads/master"}'

```
* **繞過技術**: 
    + 可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏惡意請求。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /path/to/vulnerable/repository/.git/config |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule mcp_server_git_vulnerability {
        meta:
            description = "Detects exploitation of mcp-server-git vulnerabilities"
            author = "Your Name"
        strings:
            $payload = { 28 29 2f 70 61 74 68 2f 74 6f 2f 76 75 6c 6e 65 72 61 62 6c 65 2f 72 65 70 6f 73 69 74 6f 72 79 }
        condition:
            $payload at offset 0
    }
    
    ```
 

```

snort
alert tcp any any -> any any (msg:"mcp-server-git vulnerability detected"; content:"|28 29 2f 70 61 74 68 2f 74 6f 2f 76 75 6c 6e 65 72 61 62 6c 65 2f 72 65 70 6f 73 69 74 6f 72 79|"; sid:1000001; rev:1;)

```
* **緩解措施**:
    + 更新 mcp-server-git 至最新版本。
    + 在 `nginx.conf` 中添加以下設定以防止路徑遍歷：

```

nginx
location / {
    try_files $uri $uri/ =404;
}

```

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Path Traversal (路徑遍歷)**: 想像你在檔案系統中導航，從一個目錄移動到另一個目錄。技術上是指攻擊者可以存取超出預期的檔案或目錄，通常是因為缺乏適當的路徑驗證。
* **Argument Injection (引數注入)**: 想像你在命令列中傳遞引數給一個程式。技術上是指攻擊者可以注入惡意引數給程式，從而執行未經授權的動作。
* **Prompt Injection (提示注入)**: 想像你在 AI 助手中輸入提示。技術上是指攻擊者可以注入惡意提示給 AI 助手，從而執行未經授權的動作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


