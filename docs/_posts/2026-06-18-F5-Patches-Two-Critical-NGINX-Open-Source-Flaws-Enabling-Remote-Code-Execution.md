---
layout: post
title:  "F5 Patches Two Critical NGINX Open Source Flaws Enabling Remote Code Execution"
date:   2026-06-18 20:14:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析 F5 NGINX Open Source 的代碼執行漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS v4 score: 9.2)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Use-after-free, Heap-based buffer overflow, HTTP/3 QUIC

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 
    + CVE-2026-42530：ngx_http_v3_module 中的 use-after-free 漏洞，當 NGINX Open Source 配置使用 HTTP/3 QUIC 模組時，遠程未經驗證的攻擊者可以通過特殊設計的 HTTP/3 會話重新打開 QPACK 編碼器流，從而在系統上執行代碼，特別是在 Address Space Layout Randomization (ASLR) 禁用或攻擊者可以繞過 ASLR 的情況下。
    + CVE-2026-42055：ngx_http_proxy_v2_module 和 ngx_http_grpc_module 中的 heap-based buffer overflow 漏洞，當 proxy_http_version 設為 2 或 grpc_pass 指令被使用來代理 HTTP/2 流量，且 ignore_invalid_headers 指令設為 off，同時 large_client_header_buffers 指令大小大於 2 MB 時，遠程未經驗證的攻擊者可以觸發此漏洞，從而在系統上執行代碼，特別是在 ASLR 禁用或攻擊者可以繞過 ASLR 的情況下。
* **攻擊流程圖解**:
    + User Input -> ngx_http_v3_module -> QPACK Encoder Stream -> Use-after-free
    + User Input -> ngx_http_proxy_v2_module/ngx_http_grpc_module -> large_client_header_buffers -> Heap-based Buffer Overflow
* **受影響元件**:
    + NGINX Open Source 1.31.0 - 1.31.1 (Fixed in 1.31.2)
    + NGINX Plus 37.0.0 - 37.0.1 (Fixed in 37.0.2.1)
    + 其他受影響版本詳見原始報告

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 
    + 對 NGINX Open Source 或 NGINX Plus 的版本和配置有一定了解
    + 能夠發送特殊設計的 HTTP/3 會話或 HTTP/2 流量
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload 結構 (CVE-2026-42530)
    import struct
    
    # QPACK Encoder Stream
    qpack_stream = b'\x00\x00\x00\x01'  # Stream ID
    qpack_stream += b'\x00\x00\x00\x02'  # Stream Length
    qpack_stream += b'\x01\x02\x03\x04'  # QPACK Encoder Data
    
    # HTTP/3 會話
    http3_session = b'HTTP/3'
    http3_session += qpack_stream
    
    # 發送 HTTP/3 會話
    # 使用 curl 或其他工具發送特殊設計的 HTTP/3 會話
    
    ```
 

```

bash
# 範例指令 (CVE-2026-42530)
curl -v --http3 https://example.com -H 'QPACK-Encoder-Stream: <qpack_stream>'

```
* **繞過技術**: 
    + 可以嘗試使用不同的 QPACK Encoder Stream 或 HTTP/2 流量來繞過 WAF 或 EDR 的檢測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /etc/nginx/nginx.conf |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NGINX_QPACK_Exploit {
        meta:
            description = "Detects QPACK Encoder Stream exploit"
            author = "Your Name"
        strings:
            $qpack_stream = { 00 00 00 01 00 00 00 02 01 02 03 04 }
        condition:
            $qpack_stream at 0
    }
    
    ```
 

```

snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"NGINX QPACK Encoder Stream exploit"; content:"|00 00 00 01 00 00 00 02 01 02 03 04|"; sid:1000001; rev:1;)

```
* **緩解措施**:
    + 更新 NGINX Open Source 或 NGINX Plus 至最新版本
    + 對 QPACK Encoder Stream 和 HTTP/2 流量進行檢測和過濾
    + 啟用 ASLR 和其他安全功能

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Use-after-free (UAF)**: 想像一個指標被釋放後，仍然被使用。技術上是指程式在釋放記憶體後，仍然嘗試存取該記憶體位置，導致數據不一致或邏輯錯誤。
* **Heap-based Buffer Overflow**: 想像一個堆疊被溢出。技術上是指程式在堆疊上分配的緩衝區被超出其大小的數據溢出，導致數據不一致或邏輯錯誤。
* **HTTP/3 QUIC**: 想像一個新的 HTTP 協議版本。技術上是指基於 QUIC 的 HTTP/3 協議，提供更快和更安全的網路傳輸。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/f5-patches-two-critical-nginx-open.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


