---
layout: post
title:  "Google Chrome may soon block New Tab hijacker extensions by default"
date:   2026-08-02 18:59:03 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Google Chrome 擋阻新分頁劫持擴充功能的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Chrome 擴充功能`, `政策控制`, `新分頁劫持`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Chrome 的政策控制機制允許企業管理員強制安裝擴充功能和控制瀏覽器設定，但這個機制也被惡意程式利用來劫持新分頁和修改預設搜尋引擎。
* **攻擊流程圖解**: 
    1. 惡意程式在用戶的電腦上安裝一個政策控制的擴充功能。
    2. 擴充功能修改 Chrome 的新分頁和預設搜尋引擎設定。
    3. 用戶無法移除或停用這個擴充功能，因為 Chrome 認為它是由管理員安裝的。
* **受影響元件**: Google Chrome 的所有版本，特別是那些使用政策控制的企業環境。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意程式需要在用戶的電腦上執行並具有足夠的權限來修改 Chrome 的政策控制設定。
* **Payload 建構邏輯**:

    ```
    
    python
        # 範例 Payload
        payload = {
            "name": "Malicious Extension",
            "version": "1.0",
            "manifest_version": 2,
            "newtab": "https://example.com/malicious-page"
        }
    
    ```
    * **範例指令**: 惡意程式可以使用 `curl` 或 `python` 來發送一個 HTTP 請求到 Chrome 的政策控制伺服器，以安裝這個擴充功能。
* **繞過技術**: 惡意程式可以使用各種技術來繞過 Chrome 的安全機制，例如使用 `eBPF` 來修改系統呼叫或使用 `Deserialization` 來執行任意程式碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Users\username\AppData\Local\Google\Chrome\User Data\Default\Extensions\malicious-extension |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule Malicious_Extension {
            meta:
                description = "Detects malicious Chrome extensions"
                author = "Your Name"
            strings:
                $newtab = "https://example.com/malicious-page"
            condition:
                $newtab
        }
    
    ```
    * **SIEM 查詢語法**: `SELECT * FROM chrome_extensions WHERE newtab LIKE '%example.com/malicious-page%'`
* **緩解措施**: 更新 Chrome 到最新版本，停用政策控制的擴充功能，並設定 Chrome 的安全設定以防止惡意程式修改設定。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **政策控制 (Policy Control)**: 一種機制，允許企業管理員控制和管理用戶的瀏覽器設定和擴充功能。
* **新分頁劫持 (New Tab Hijacking)**: 一種攻擊技術，惡意程式修改用戶的新分頁設定，以將用戶導向惡意網站。
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 核心技術，允許用戶空間程式碼修改系統呼叫和監視系統活動。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/google/google-chrome-may-soon-block-new-tab-hijacker-extensions-by-default/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1218/)


