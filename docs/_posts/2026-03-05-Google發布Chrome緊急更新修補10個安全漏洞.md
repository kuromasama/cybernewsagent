---
layout: post
title:  "Google發布Chrome緊急更新修補10個安全漏洞"
date:   2026-03-05 12:44:19 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Chrome 瀏覽器圖形轉譯元件 ANGLE 中的整數溢位漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Heap Spraying, Integer Overflow, Use-After-Free

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞出現在 Chrome 瀏覽器的圖形轉譯元件 ANGLE 中，具體是在 `eglCreateImage` 函數中沒有檢查整數溢位，導致當創建圖像時，若圖像大小超過最大限制，會導致整數溢位，從而導致用戶空間的任意內存寫入。
* **攻擊流程圖解**:
  1. 攻擊者創建一個大於最大限制的圖像。
  2. `eglCreateImage` 函數因為整數溢位而返回一個小於實際大小的圖像大小。
  3. 攻擊者可以利用這個小於實際大小的圖像大小來寫入任意內存。
* **受影響元件**: Chrome 瀏覽器版本 145.0.7632.159 與 145.0.7632.160。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限創建圖像，並且需要知道受影響的 Chrome 瀏覽器版本。
* **Payload 建構邏輯**:

    ```
    
    python
    import ctypes
    
    # 創建一個大於最大限制的圖像
    image_size = 0xFFFFFFFF  # 整數溢位
    
    # 創建圖像
    image = ctypes.create_string_buffer(image_size)
    
    # 寫入任意內存
    ctypes.memset(image, 0x41, image_size)  # 寫入 'A' 字元
    
    ```
* **繞過技術**: 攻擊者可以利用 WAF 的繞過技巧，例如使用 Base64 編碼來繞過圖像大小檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/image.png |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Chrome_ANGLE_Vulnerability {
      meta:
        description = "Detects Chrome ANGLE vulnerability"
        author = "Your Name"
      strings:
        $image_size = { 0xFF 0xFF 0xFF 0xFF }  # 整數溢位
      condition:
        $image_size at 0
    }
    
    ```
* **緩解措施**: 更新 Chrome 瀏覽器版本至 145.0.7632.159 或以上。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Integer Overflow (整數溢位)**: 想像一個整數變數的值超過了最大限制，導致變數的值被設為一個小於實際值的值。技術上是指當一個整數變數的值超過了最大限制時，會導致變數的值被設為一個小於實際值的值。
* **Use-After-Free (用後釋放)**: 想像一個指針指向了一塊已經被釋放的內存。技術上是指當一個指針指向了一塊已經被釋放的內存時，會導致指針的值被設為一個無效的值。
* **Heap Spraying (堆疊噴灑)**: 想像一個攻擊者創建了一個大於最大限制的堆疊，導致堆疊的大小超過了最大限制。技術上是指當一個攻擊者創建了一個大於最大限制的堆疊時，會導致堆疊的大小超過了最大限制，從而導致堆疊的內存被寫入任意內存。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174224)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


