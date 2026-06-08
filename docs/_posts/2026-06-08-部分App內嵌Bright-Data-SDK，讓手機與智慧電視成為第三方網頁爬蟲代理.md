---
layout: post
title:  "部分App內嵌Bright Data SDK，讓手機與智慧電視成為第三方網頁爬蟲代理"
date:   2026-06-08 10:25:29 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Bright Data SDK 的住宅代理網路技術與風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `WebSocket`, `Proxy`, `SDK`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Bright Data SDK 在取得使用者同意後，會讓手機或智慧電視成為住宅代理網路的一部分，協助第三方客戶透過一般家庭IP執行網頁資料抓取。這個過程中，SDK會取得遠端設定檔，建立到Bright Data相關網域的WebSocket連線，回報裝置是否連上Wi-Fi、電量、CPU與記憶體使用率與SDK版本等資訊。
* **攻擊流程圖解**: 
    1. 使用者安裝包含Bright Data SDK的App。
    2. 使用者同意App內與Bright Data相關的說明或選項。
    3. SDK啟動後，取得遠端設定檔。
    4. SDK建立到Bright Data相關網域的WebSocket連線。
    5. SDK回報裝置是否連上Wi-Fi、電量、CPU與記憶體使用率與SDK版本等資訊。
* **受影響元件**: Bright Data SDK、包含Bright Data SDK的App。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者必須安裝包含Bright Data SDK的App，並同意App內與Bright Data相關的說明或選項。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建立WebSocket連線
    ws = requests.get("wss://example.com/ws")
    
    # 回報裝置是否連上Wi-Fi、電量、CPU與記憶體使用率與SDK版本等資訊
    data = {
        "device_info": {
            "wifi": True,
            "battery": 50,
            "cpu": 20,
            "memory": 30,
            "sdk_version": "1.0.0"
        }
    }
    
    # 送出請求
    response = requests.post("https://example.com/report", json=data)
    
    ```
    *範例指令*: 使用`curl`工具送出請求。

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"device_info": {"wifi": true, "battery": 50, "cpu": 20, "memory": 30, "sdk_version": "1.0.0"}}' https://example.com/report

```
* **繞過技術**: 使用者開啟VPN可能無法攔截該連線，因為SDK可使用Apple提供的網路介面指定機制，讓部分代理流量直接走Wi-Fi或行動網路介面。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /ws |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule BrightData_SDK {
        meta:
            description = "Detect Bright Data SDK"
            author = "Your Name"
        strings:
            $a = "wss://example.com/ws"
        condition:
            $a
    }
    
    ```
    或者是具體的SIEM查詢語法 (Splunk/Elastic)。

```

sql
index=your_index (src_ip="your_src_ip" AND dest_ip="your_dest_ip" AND http_method="POST" AND http_uri="/report")

```
* **緩解措施**: 封鎖Bright Data SDK相關網域，或者在DNS或網路閘道層封鎖相關流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **WebSocket (WebSocket)**: 一種讓網頁瀏覽器和伺服器之間可以進行全雙工通訊的技術。想像兩個人同時在聊天室中聊天。技術上是指使用WebSocket協定建立的連線，可以讓瀏覽器和伺服器之間進行即時通訊。
* **Proxy (代理)**: 一種讓使用者可以透過中間伺服器存取其他伺服器的技術。想像一個郵局，可以幫助你將信件送到其他地方。技術上是指使用代理伺服器轉發請求和回應。
* **SDK (軟體開發工具包)**: 一種讓開發者可以使用特定功能或服務的工具包。想像一個工具箱，可以幫助你完成特定任務。技術上是指使用SDK提供的API和函數庫來開發應用程式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176437)
- [MITRE ATT&CK](https://attack.mitre.org/)


