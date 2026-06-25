---
layout: post
title:  "Order-tracking app Shop abused to push callback phishing attacks"
date:   2026-06-25 19:49:49 +0000
categories: [security]
severity: high
---

# 🔥 解析 Shop 應用程式的回呼釣魚攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak 和 RCE
> * **關鍵技術**: 社交工程、回呼釣魚、遠端存取軟體

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Shop 應用程式的設計允許攻擊者插入假購買收據，從而欺騙用戶提供敏感資料或安裝遠端存取軟體。
* **攻擊流程圖解**: 
  1. 攻擊者創建假購買收據並插入用戶的訂單歷史中。
  2. 用戶收到通知並聯繫客服電話。
  3. 攻擊者假裝客服人員，嘗試說服用戶提供敏感資料或安裝遠端存取軟體。
* **受影響元件**: Shop 應用程式（版本號未指定），適用於 Android 和 iOS 平台。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建假購買收據並插入用戶的訂單歷史中。
* **Payload 建構邏輯**: 
    * 假購買收據包含客服電話號碼，當用戶聯繫客服時，攻擊者假裝客服人員。
    * 攻擊者使用社交工程技術說服用戶提供敏感資料或安裝遠端存取軟體。

```

python
# 範例 Payload
class FakeReceipt:
    def __init__(self, order_id, customer_service_phone):
        self.order_id = order_id
        self.customer_service_phone = customer_service_phone

    def send_notification(self):
        # 發送通知給用戶
        print(f"您的訂單 {self.order_id} 已經處理完成。如有任何問題，請聯繫客服 {self.customer_service_phone}")

```
* **繞過技術**: 攻擊者可以使用社交工程技術來繞過用戶的警惕性。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 未指定 | 未指定 | 未指定 | 未指定 |* **偵測規則 (Detection Rules)**:
    * YARA Rule:

    ```
    
    yara
    rule FakeReceipt {
        meta:
            description = "偵測假購買收據"
            author = "您的名字"
        strings:
            $fake_receipt = "您的訂單 .* 已經處理完成。如有任何問題，請聯繫客服 .*"
        condition:
            $fake_receipt
    }
    
    ```
    * Snort/Suricata Signature:

    ```
    
    snort
    alert tcp any any -> any any (msg:"偵測假購買收據"; content:"您的訂單 .* 已經處理完成。如有任何問題，請聯繫客服 .*"; sid:1000001; rev:1;)
    
    ```
* **緩解措施**: 用戶應該在收到通知時，直接聯繫商家客服確認訂單狀態，而不是聯繫客服電話號碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社交工程 (Social Engineering)**: 想像攻擊者使用心理操控來欺騙用戶提供敏感資料。技術上是指攻擊者使用各種手段來欺騙用戶，例如假冒客服人員或發送假通知。
* **回呼釣魚 (Callback Phishing)**: 想像攻擊者發送假通知給用戶，當用戶聯繫客服時，攻擊者假裝客服人員。技術上是指攻擊者使用假通知來欺騙用戶聯繫客服電話號碼。
* **遠端存取軟體 (Remote Access Software)**: 想像攻擊者使用軟體來控制用戶的設備。技術上是指攻擊者使用軟體來控制用戶的設備，例如 TeamViewer 或 Remote Desktop。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/order-tracking-app-shop-abused-to-push-callback-phishing-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


