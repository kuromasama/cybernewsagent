---
layout: post
title:  "Microsoft Teams right-click paste broken by Edge update bug"
date:   2026-04-18 18:38:14 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Edge 更新導致的 Microsoft Teams 右鍵貼上漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Use-after-free`, `Heap Spraying`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft Edge 更新導致的程式碼回歸（code regression）導致 Microsoft Teams 中的右鍵貼上功能失效。這是由於 Microsoft Edge 的更新導致 Teams 中的某些功能無法正常工作。
* **攻擊流程圖解**: 
    1. 使用者嘗試在 Microsoft Teams 中使用右鍵貼上功能。
    2. Microsoft Teams 嘗試呼叫 Microsoft Edge 的 API 進行貼上操作。
    3. 由於 Microsoft Edge 的更新導致的程式碼回歸，API 呼叫失敗，導致右鍵貼上功能失效。
* **受影響元件**: Microsoft Teams 桌面客戶端，Microsoft Edge 瀏覽器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要有 Microsoft Teams 和 Microsoft Edge 的使用權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建構 payload
    payload = {
        "url": "https://example.com",
        "text": "example text"
    }
    
    # 發送請求
    response = requests.post("https://example.com/paste", json=payload)
    
    ```
    * **範例指令**: 使用 `curl` 命令發送請求。

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"url": "https://example.com", "text": "example text"}' https://example.com/paste

```
* **繞過技術**: 可以使用 `eBPF` 技術繞過某些安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Teams_Paste_Vulnerability {
        meta:
            description = "Detects Microsoft Teams paste vulnerability"
            author = "Your Name"
        strings:
            $url = "https://example.com"
            $text = "example text"
        condition:
            all of them
    }
    
    ```
    * **SIEM 查詢語法**:

    ```
    
    sql
    SELECT * FROM logs WHERE url = "https://example.com" AND text = "example text"
    
    ```
* **緩解措施**: 更新 Microsoft Edge 和 Microsoft Teams 至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Use-after-free (用後釋放)**: 想像你有一個記憶體區塊，你使用它然後釋放它。但是，如果你在釋放後仍然嘗試使用它，就會發生用後釋放的錯誤。技術上是指程式嘗試存取已經釋放的記憶體區塊。
* **Heap Spraying (堆疊噴灑)**: 想像你有一個堆疊，你嘗試在堆疊中噴灑某些資料，以便在堆疊中找到這些資料。技術上是指程式嘗試在堆疊中分配大量的記憶體區塊，以便在堆疊中找到某些資料。
* **eBPF (擴展伯克利封包過濾器)**: 想像你有一個網路封包過濾器，你可以使用它來過濾網路封包。技術上是指一種 Linux 內核技術，允許用戶空間程式碼在內核中執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-teams-right-click-paste-broken-by-edge-update-bug/)
- [MITRE ATT&CK](https://attack.mitre.org/)


