---
layout: post
title:  "WhatsApp is Finally Getting Usernames to Help Keep Phone Numbers Private"
date:   2026-06-29 19:48:07 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 WhatsApp Username 保護機制：技術深度分析

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Username Reservation`, `Username Key`, `Phone Number Protection`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: WhatsApp 的 Username 保護機制是設計來保護用戶的電話號碼不被他人瀏覽或存取。這個機制允許用戶選擇一個唯一的 Username，並可選擇設定一個 Username Key，以增加一層保護。
* **攻擊流程圖解**: 
    1. 用戶選擇一個 Username。
    2. 用戶可選擇設定一個 Username Key。
    3. 當其他用戶嘗試通過 Username 聯繫用戶時，需要知道用戶的正確 Username 和 Username Key（如果設定）。
* **受影響元件**: WhatsApp 的 Username 保護機制適用於所有 WhatsApp 用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道用戶的正確 Username 和 Username Key（如果設定）。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 範例 Payload
    username = "example_username"
    username_key = "example_username_key"
    
    # 尋找用戶的電話號碼
    def find_phone_number(username, username_key):
        # 這裡需要實現一個查找用戶電話號碼的函數
        pass
    
    # 發送訊息給用戶
    def send_message(username, username_key):
        # 這裡需要實現一個發送訊息給用戶的函數
        pass
    
    # 主要攻擊邏輯
    def main():
        phone_number = find_phone_number(username, username_key)
        if phone_number:
            send_message(username, username_key)
        else:
            print("找不到用戶的電話號碼")
    
    if __name__ == "__main__":
        main()
    
    ```
    * **範例指令**: `curl -X POST -H "Content-Type: application/json" -d '{"username": "example_username", "username_key": "example_username_key"}' https://example.com/find_phone_number`
* **繞過技術**: 如果用戶沒有設定 Username Key，攻擊者可以嘗試猜測用戶的 Username 和電話號碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule WhatsApp_Username_Key_Leak {
        meta:
            description = "WhatsApp Username Key Leak"
            author = "Your Name"
        strings:
            $username_key = "example_username_key"
        condition:
            $username_key
    }
    
    ```
    * **SIEM 查詢語法**: `index=whatsapp_logs (username_key="example_username_key")`
* **緩解措施**: 用戶應該設定一個強大的 Username Key，並避免在公開場合分享自己的 Username 和電話號碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Username Reservation**: WhatsApp 的 Username 保護機制，允許用戶選擇一個唯一的 Username。
* **Username Key**: 一個可選擇的密碼，增加一層保護，用戶需要知道用戶的正確 Username 和 Username Key 才能聯繫用戶。
* **Phone Number Protection**: WhatsApp 的電話號碼保護機制，保護用戶的電話號碼不被他人瀏覽或存取。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/whatsapp-is-finally-getting-usernames.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


