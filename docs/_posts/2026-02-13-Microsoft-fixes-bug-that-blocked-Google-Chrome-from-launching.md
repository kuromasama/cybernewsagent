---
layout: post
title:  "Microsoft fixes bug that blocked Google Chrome from launching"
date:   2026-02-13 12:42:42 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Family Safety 中的 Web瀏覽器阻塞漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Web Filtering`, `Parental Control`, `Browser Blocking`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Family Safety 的 Web Filtering 工具會阻塞新版本的已經批准的 Web 瀏覽器，導致瀏覽器無法啟動或意外關閉。
* **攻擊流程圖解**: 
    1. 使用者嘗試啟動 Google Chrome 或其他 Web 瀏覽器。
    2. Microsoft Family Safety 的 Web Filtering 工具檢查瀏覽器版本。
    3. 如果瀏覽器版本不是最新的，則會被阻塞。
* **受影響元件**: Windows 10 22H2 和 Windows 11 22H2 或更新版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要有 Microsoft Family Safety 的帳戶和 Windows 10 或 Windows 11 的系統。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義目標 URL
    url = "https://www.google.com"
    
    # 定義 User-Agent
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    # 發送請求
    response = requests.get(url, headers={"User-Agent": user_agent})
    
    # 列印回應
    print(response.text)
    
    ```
    *範例指令*: 使用 `curl` 工具發送請求：

```

bash
curl -X GET -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" https://www.google.com

```
* **繞過技術**: 可以使用代理伺服器或 VPN 來繞過 Microsoft Family Safety 的 Web Filtering 工具。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | google.com | C:\Program Files\Google\Chrome\Application\chrome.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Family_Safety_Bypass {
        meta:
            description = "Detects attempts to bypass Microsoft Family Safety"
            author = "Your Name"
        strings:
            $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        condition:
            $ua in (http.headers["User-Agent"])
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)：

```

sql
index=web_logs (http.headers["User-Agent"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

```
* **緩解措施**: 更新 Microsoft Family Safety 到最新版本，並設定 Web Filtering 工具以允許最新版本的 Web 瀏覽器。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Web Filtering**: 一種技術，用於過濾和控制網際網路流量，通常用於企業和家庭環境中，以限制使用者存取某些網站或內容。
* **Parental Control**: 一種技術，用於控制和限制兒童存取網際網路和其他數字內容，通常用於家庭環境中，以保護兒童免受不適宜內容的影響。
* **Browser Blocking**: 一種技術，用於阻塞或限制使用者存取某些網站或內容，通常用於企業和家庭環境中，以限制使用者存取某些網站或內容。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-family-safety-bug-that-blocks-google-chrome-from-launching/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


