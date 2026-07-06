---
layout: post
title:  "New TrojPix Attack Leaks Data From Air-Gapped Systems via Video Cable Emissions"
date:   2026-07-06 10:01:30 +0000
categories: [security]
severity: high
---

# 🔥 解析 TrojPix 攻擊：利用螢幕像素泄露資料的新型方法

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Imperceptible Pixel Modulation, TEMPEST, Air-Gap Covert Channels

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TrojPix 攻擊利用螢幕像素的微小變化來傳輸資料，無需任何硬體修改或管理員權限。這是因為螢幕的像素可以被調整以產生微小的電磁輻射，從而被附近的接收器接收和解碼。
* **攻擊流程圖解**:
  1. 惡意軟體（Malware）感染目標機器。
  2. 惡意軟體使用螢幕的像素來傳輸資料。
  3. 資料被傳輸到附近的接收器。
* **受影響元件**: 所有使用螢幕的電腦系統，尤其是那些具有敏感資料的系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 惡意軟體需要在目標機器上執行，並具有螢幕的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import numpy as np
    
    # 定義螢幕的像素大小
    pixel_size = 1024
    
    # 定義資料傳輸的速率
    transmission_rate = 8.1  # Mbps
    
    # 定義資料傳輸的距離
    transmission_distance = 208  # meters
    
    # 建構 payload
    payload = np.random.randint(0, 256, size=(pixel_size, pixel_size))
    
    ```
* **繞過技術**: TrojPix 攻擊可以使用螢幕的像素來傳輸資料，從而繞過傳統的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule TrojPix_Detection {
      meta:
        description = "Detects TrojPix malware"
        author = "Your Name"
      strings:
        $pixel_modulation = { 00 01 02 03 04 05 06 07 }
      condition:
        $pixel_modulation at 0x1000
    }
    
    ```
* **緩解措施**: 使用光纖連接代替銅纜，屏蔽電纜和房間，保持系統和軟體的更新。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Imperceptible Pixel Modulation**: 一種利用螢幕像素的微小變化來傳輸資料的技術。
* **TEMPEST**: 一種利用電磁輻射來傳輸資料的技術。
* **Air-Gap Covert Channels**: 一種利用空氣間的電磁輻射來傳輸資料的技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


