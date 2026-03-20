---
layout: post
title:  "Stripe與Tempo共推MPP，要把AI代理付款接進既有金流體系"
date:   2026-03-20 01:27:10 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 MPP 協定與機器支付的安全性
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: 付款流程中的授權繞過
> * **關鍵技術**: `HTTP 402`, `PaymentIntents API`, `SPT`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: MPP 協定的授權機制可能存在缺陷，允許攻擊者繞過授權流程，直接取得付款資源。
* **攻擊流程圖解**: 
    1. 攻擊者向 API 請求付費資源。
    2. 伺服器回傳 HTTP 402 與付款資訊。
    3. 攻擊者模擬授權流程，重新送出請求。
    4. 伺服器驗證授權失敗，但仍允許攻擊者取得付款資源。
* **受影響元件**: MPP 協定、PaymentIntents API、SPT。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 MPP 協定的授權機制和 PaymentIntents API 的使用方式。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 模擬授權流程
    def simulate_authorization():
        # ...
    
    # 送出請求
    def send_request():
        url = "https://example.com/payment"
        headers = {"Authorization": "Bearer <token>"}
        response = requests.post(url, headers=headers)
        return response
    
    # 攻擊者模擬授權流程
    simulate_authorization()
    
    # 送出請求
    response = send_request()
    print(response.text)
    
    ```
    * **範例指令**: `curl -X POST -H "Authorization: Bearer <token>" https://example.com/payment`
* **繞過技術**: 攻擊者可以使用 HTTP 402 的回應來模擬授權流程，繞過授權機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule MPP_Authorization_Bypass {
        meta:
            description = "MPP 授權繞過攻擊"
            author = "..."
        strings:
            $http_402 = "HTTP/1.1 402 Payment Required"
        condition:
            $http_402
    }
    
    ```
    * **SIEM 查詢語法**: `SELECT * FROM logs WHERE http_status_code = 402`
* **緩解措施**: 更新 MPP 協定和 PaymentIntents API 的授權機制，強化授權流程的安全性。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **MPP (Machine Payments Protocol)**: 一種機器支付協定，允許機器之間進行付款流程。
* **PaymentIntents API**: 一種用於處理付款的 API，允許商家創建和管理付款意圖。
* **SPT (Shared Payment Tokens)**: 一種共享付款憑證，允許用戶授權商家進行付款。

## 5. 🔗 參考文獻與延伸閱讀
- [MPP 協定官方文件](https://www.mpp.org/)
- [PaymentIntents API 文件](https://www.paymentintents.com/)
- [SPT 文件](https://www.spt.org/)


