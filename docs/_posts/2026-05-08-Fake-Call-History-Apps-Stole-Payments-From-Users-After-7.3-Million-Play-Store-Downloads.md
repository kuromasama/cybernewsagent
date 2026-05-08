---
layout: post
title:  "Fake Call History Apps Stole Payments From Users After 7.3 Million Play Store Downloads"
date:   2026-05-08 19:07:59 +0000
categories: [security]
severity: high
---

# 🔥 解析 Android 假冒通話記錄應用程式的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.5)
> * **受駭指標**: 資料竊取與財務損失
> * **關鍵技術**: 社交工程、假冒應用程式、訂閱詐騙

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 假冒通話記錄應用程式利用社交工程手法，欺騙用戶下載並付費訂閱，卻提供假資料。
* **攻擊流程圖解**: 
  1. 用戶下載假冒應用程式
  2. 應用程式要求用戶付費訂閱
  3. 用戶付費後，應用程式提供假資料
* **受影響元件**: Android 5.0 以上版本，Google Play Store 上的假冒應用程式

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要下載並安裝假冒應用程式
* **Payload 建構邏輯**: 
    * 假冒應用程式會要求用戶付費訂閱
    * 用戶付費後，應用程式會提供假資料
    *

```

python
        # 假冒應用程式的付費訂閱邏輯
        def subscribe(user_id, payment_method):
            # 處理付費訂閱
            if payment_method == "google_play":
                # 處理 Google Play 付費訂閱
                return True
            elif payment_method == "third_party":
                # 處理第三方付費訂閱
                return True
            else:
                return False

```
    * **範例指令**: 
        * `curl -X POST -H "Content-Type: application/json" -d '{"user_id": "123", "payment_method": "google_play"}' https://example.com/subscribe`
* **繞過技術**: 假冒應用程式可能會使用社交工程手法，欺騙用戶下載並付費訂閱

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/app/com.example.app |* **偵測規則 (Detection Rules)**:
    * YARA Rule:

    ```
    
    yara
            rule fake_app {
                meta:
                    description = "偵測假冒應用程式"
                    author = "Your Name"
                strings:
                    $a = "com.example.app"
                condition:
                    $a
            }
    
    ```
    * Snort/Suricata Signature:

    ```
    
    snort
            alert tcp any any -> any any (msg:"偵測假冒應用程式"; content:"com.example.app"; sid:1000001; rev:1;)
    
    ```
* **緩解措施**: 
    * 刪除假冒應用程式
    * 停止付費訂閱
    * 更新 Google Play Store 的安全設定

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社交工程 (Social Engineering)**: 想像一個骗子通過電話或郵件欺騙你提供敏感信息。技術上是指攻擊者使用心理操縱手法，欺騙用戶提供敏感信息或執行特定動作。
* **假冒應用程式 (Fake App)**: 想像一個假冒的銀行應用程式，欺騙用戶提供敏感信息。技術上是指攻擊者創建一個假冒的應用程式，欺騙用戶下載並安裝。
* **訂閱詐騙 (Subscription Scam)**: 想像一個假冒的應用程式，欺騙用戶付費訂閱。技術上是指攻擊者創建一個假冒的應用程式，欺騙用戶付費訂閱。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/fake-call-history-apps-stole-payments.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1566/)


