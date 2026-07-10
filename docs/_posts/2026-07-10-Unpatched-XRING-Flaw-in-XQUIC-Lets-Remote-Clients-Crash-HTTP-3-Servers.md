---
layout: post
title:  "Unpatched XRING Flaw in XQUIC Lets Remote Clients Crash HTTP/3 Servers"
date:   2026-07-10 14:06:21 +0000
categories: [security]
severity: critical
---

# 🚨 解析 XQUIC 中的 XRING 漏洞：HTTP/3 的遠程崩潰風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Remote Crash (可能導致服務崩潰)
> * **關鍵技術**: QPACK, HTTP/3, Ring Buffer

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: XQUIC 中的 QPACK 實現存在一個錯誤的變數計算，導致當客戶端請求增加表格大小時，服務器會計算錯誤的尾部資料大小，從而導致記憶體拷貝過度，引發崩潰。
* **攻擊流程圖解**:
  1. 客戶端發送 HTTP/3 請求，啟用 QPACK。
  2. 客戶端請求增加表格大小，觸發 XQUIC 中的錯誤計算。
  3. 服務器計算錯誤的尾部資料大小，導致記憶體拷貝過度。
  4. 記憶體拷貝過度引發崩潰。
* **受影響元件**: XQUIC 1.9.4 版本及之前的所有版本，包括 Tengine 和其他使用 XQUIC 的服務器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 無需登錄，無需惡意封包。
* **Payload 建構邏輯**:

    ```
    
    http
      GET / HTTP/3
      Host: example.com
      Accept: */*
      qpack-table-size: 64
      qpack-table-size: 65
    
    ```
  客戶端可以通過發送這樣的請求來觸發服務器的崩潰。
* **繞過技術**: 無需繞過技術，因為這個漏洞不需要惡意封包。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| HTTP 方法 | GET |
| HTTP 版本 | HTTP/3 |
| qpack-table-size | 64, 65 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule XQUIC_XRING {
        meta:
          description = "XQUIC XRING 漏洞偵測"
          author = "Your Name"
        strings:
          $http_get = "GET / HTTP/3"
          $qpack_table_size = "qpack-table-size: 64"
          $qpack_table_size_2 = "qpack-table-size: 65"
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 設定 `SETTINGS_QPACK_MAX_TABLE_CAPACITY` 為 0，關閉 QPACK 的動態表格功能，或者停用 HTTP/3 支持。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **QPACK (QUIC 封包壓縮)**: 一種用於 HTTP/3 的封包壓縮算法，旨在減少封包大小，提高傳輸效率。
* **Ring Buffer (環形緩衝區)**: 一種資料結構，使用一個固定大小的緩衝區，當資料寫入緩衝區時，若緩衝區已滿，則從緩衝區的開始位置開始覆蓋。
* **HTTP/3 (超文本傳輸協議第三版)**: 一種新的 HTTP 版本，基於 QUIC 協議，旨在提高傳輸效率和安全性。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/unpatched-xring-flaw-in-xquic-lets.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


