---
layout: post
title:  "Student hacked Taiwan high-speed rail to trigger emergency brakes"
date:   2026-05-05 19:10:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TETRA 通信系統漏洞：利用軟件定義無線電和手持式無線電進行攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: 軟件定義無線電 (SDR), 手持式無線電, TETRA 通信系統

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TETRA 通信系統的參數沒有被定期輪換，導致攻擊者可以攔截和解碼這些參數，進而使用軟件定義無線電和手持式無線電進行攻擊。
* **攻擊流程圖解**:
  1. 攻擊者使用軟件定義無線電攔截 TETRA 通信系統的參數。
  2. 攻擊者解碼攔截到的參數。
  3. 攻擊者使用手持式無線電傳送偽造的 "General Alarm" 信號。
  4. TETRA 通信系統接收到偽造的 "General Alarm" 信號，觸發緊急制動程序。
* **受影響元件**: TETRA 通信系統，特別是使用了 19 年沒有輪換參數的系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個軟件定義無線電和手持式無線電，以及 TETRA 通信系統的參數。
* **Payload 建構邏輯**:

    ```
    
    python
    import numpy as np
    
    # 定義 TETRA 通信系統的參數
    tetra_params = {
        'frequency': 400.0,  # MHz
        'modulation': 'QPSK',
        'symbol_rate': 10000  # symbols per second
    }
    
    # 定義偽造的 "General Alarm" 信號
    alarm_signal = np.array([1, 0, 1, 0, 1, 0, 1, 0])
    
    # 使用軟件定義無線電傳送偽造的 "General Alarm" 信號
    def send_alarm_signal(alarm_signal, tetra_params):
        # 實現軟件定義無線電的傳送邏輯
        pass
    
    send_alarm_signal(alarm_signal, tetra_params)
    
    ```
* **繞過技術**: 攻擊者可以使用軟件定義無線電和手持式無線電來繞過 TETRA 通信系統的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule tetra_alarm_signal {
        meta:
            description = "偵測 TETRA 通信系統的 'General Alarm' 信號"
            author = "Your Name"
        strings:
            $alarm_signal = { 01 00 01 00 01 00 01 00 }
        condition:
            $alarm_signal
    }
    
    ```
* **緩解措施**: 定期輪換 TETRA 通信系統的參數，使用安全的傳輸協議，例如加密和認證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TETRA (Terrestrial Trunked Radio)**: 一種無線通信系統，使用於公共安全和緊急服務。
* **軟件定義無線電 (Software-Defined Radio, SDR)**: 一種無線電通信系統，使用軟件來實現無線電的功能。
* **手持式無線電 (Handheld Radio)**: 一種小型、便攜的無線電通信設備。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/student-hacked-taiwan-high-speed-rail-to-trigger-emergency-brakes/)
- [TETRA 通信系統](https://en.wikipedia.org/wiki/Terrestrial_Trunked_Radio)
- [軟件定義無線電](https://en.wikipedia.org/wiki/Software-defined_radio)


