---
layout: post
title:  "數發部資安署實測四款中國App，同是導航地圖，高德比Google Maps更危險"
date:   2026-05-27 15:03:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析中國App的資安風險：高德地圖、嗶哩嗶哩、愛奇藝及BIMOBIMO的隱私侵害

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: 資料外洩、隱私侵害
> * **關鍵技術**: 黑箱檢測、反組譯、開源檢測工具

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 高德地圖等中國App存在過度蒐集使用者資料的行為，包括讀取剪貼簿、地理位置、健康紀錄等。
* **攻擊流程圖解**: 
    1. 使用者下載並安裝高德地圖等中國App。
    2. App要求使用者授權存取敏感權限，例如讀取剪貼簿、地理位置等。
    3. App在背景持續讀取並記錄使用者的行動軌跡、健康紀錄等資料。
    4. 資料被傳輸至中國境內伺服器，可能被中國政府調取。
* **受影響元件**: 高德地圖、嗶哩嗶哩、愛奇藝、BIMOBIMO等中國App。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者下載並安裝高德地圖等中國App。
* **Payload 建構邏輯**: 
    * 高德地圖等中國App可以通過讀取剪貼簿、地理位置等權限來蒐集使用者資料。
    * 資料可以被傳輸至中國境內伺服器，可能被中國政府調取。
* **繞過技術**: 高德地圖等中國App可以通過黑箱檢測、反組譯等方式來繞過安全檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
    * 高德地圖等中國App的Hash值。
    * 伺服器IP地址。
    * Domain名稱。
* **偵測規則 (Detection Rules)**:
    * YARA Rule: `rule HighRiskApp { meta: description = "High risk app" condition: (uint16(0x0) == 0x5A4D) and (uint16(0x2) == 0x4550) }`
    * Snort/Suricata Signature: `alert tcp any any -> any any (msg:"High risk app"; content:"|5A 4D|"; depth:2; sid:1000001; rev:1;)`
* **緩解措施**:
    * 刪除高德地圖等中國App。
    * 停止使用高德地圖等中國App。
    * 使用安全的App替代。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **黑箱檢測 (Black Box Testing)**: 一種軟體測試方法，測試人員不需要了解軟體的內部結構和代碼。
* **反組譯 (Reverse Engineering)**: 一種技術，通過分析軟體的二進制代碼來了解其內部結構和工作原理。
* **開源檢測工具 (Open Source Detection Tool)**: 一種工具，使用開源軟體來檢測和分析軟體的安全性。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176165)
- [MITRE ATT&CK](https://attack.mitre.org/)


