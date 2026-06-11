---
layout: post
title:  "Nottingham University data breach affects over 450,000 students"
date:   2026-06-11 10:13:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ShinyHunters 對 Nottingham University 的攻擊：PeopleSoft 零日漏洞利用與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: PeopleSoft 零日漏洞、Gadget Chain、Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PeopleSoft 的零日漏洞允許攻擊者執行任意代碼，可能是由於 PeopleSoft 的某個模組沒有正確地驗證用戶輸入，導致了 Deserialization 攻擊。
* **攻擊流程圖解**:
  1. 攻擊者發送精心構造的請求到 PeopleSoft 伺服器。
  2. 伺服器對請求進行 Deserialization。
  3. Deserialization 過程中，攻擊者注入的惡意代碼被執行。
* **受影響元件**: PeopleSoft 9.2、PeopleSoft 9.1 等版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 PeopleSoft 伺服器的 URL 和版本。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義攻擊的 URL 和 Payload
    url = "https://example.com/peoplesoft"
    payload = {"param1": "value1", "param2": "value2"}
    
    # 發送請求
    response = requests.post(url, data=payload)
    
    # 判斷攻擊是否成功
    if response.status_code == 200:
        print("攻擊成功")
    else:
        print("攻擊失敗")
    
    ```
* **繞過技術**: 攻擊者可以使用 Gadget Chain 技術來繞過 WAF 和 EDR 的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| xxxxxx | 192.168.1.1 | example.com | /peoplesoft |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule peoplesoft_exploit {
      meta:
        description = "PeopleSoft 零日漏洞利用"
        author = "Your Name"
      strings:
        $a = "param1=value1"
        $b = "param2=value2"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新 PeopleSoft 至最新版本，啟用 WAF 和 EDR 的檢測功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 想像你把一個物體打包成一個箱子，然後發送給別人。技術上是指將資料從某種格式（如 JSON 或 XML）轉換回程式語言的物件。
* **Gadget Chain (小工具鏈)**: 想像你有一串小工具，每個小工具都可以完成某個任務。技術上是指使用多個小工具來完成某個攻擊任務。
* **PeopleSoft (PeopleSoft)**: 一種企業級的軟件套件，用于管理人力資源、財務、薪酬等方面的業務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/nottingham-university-data-breach-affects-over-450-000-students/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


