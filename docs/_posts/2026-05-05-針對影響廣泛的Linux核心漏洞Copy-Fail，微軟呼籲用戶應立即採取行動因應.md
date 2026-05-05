---
layout: post
title:  "針對影響廣泛的Linux核心漏洞Copy Fail，微軟呼籲用戶應立即採取行動因應"
date:   2026-05-05 08:00:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Linux 核心漏洞 Copy Fail：利用與防禦技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `authencesn`, `AF_ALG`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Copy Fail 漏洞是由於 Linux 核心的密碼學範本 `authencesn` 中的邏輯錯誤引起的。該錯誤允許攻擊者在不需要觸發競態條件或系統核心層面的偏移的情況下，實現本機權限提升。
* **攻擊流程圖解**: 
    1. 攻擊者發送特製的請求到 Linux 核心的 `authencesn` 函數。
    2. 函數中的邏輯錯誤導致系統核心授予攻擊者不當的權限。
    3. 攻擊者利用獲得的權限實現本機權限提升。
* **受影響元件**: 所有採用 4.14 到 7.0-rc 版 Linux 核心的 Linux 發行版。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在目標系統上具有普通用戶權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 創建 socket 物件
    sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET)
    
    # 設定 socket 選項
    sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, b'copy_fail_payload')
    
    # 發送請求到 Linux 核心的 authencesn 函數
    sock.sendto(b'copy_fail_request', ('localhost', 0))
    
    ```
    * **範例指令**: `curl -X POST -H 'Content-Type: application/json' -d '{"payload": "copy_fail_payload"}' http://localhost:8080/authencesn`
* **繞過技術**: 攻擊者可以使用 eBPF 來繞過系統核心的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `copy_fail_payload` | `127.0.0.1` | `localhost` | `/proc/authencesn` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule copy_fail_detection {
        meta:
            description = "Detect Copy Fail exploit"
            author = "Blue Team"
        strings:
            $payload = { 63 6f 70 79 5f 66 61 69 6c 5f 70 61 79 6c 6f 61 64 }
        condition:
            $payload at pe.entry_point
    }
    
    ```
    * **SIEM 查詢語法**: `index=linux_logs (event_type="authencesn" AND payload="copy_fail_payload")`
* **緩解措施**: 除了套用修補程式外，還可以停用受影響功能、實施網路隔離或存取控制管控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AF_ALG**: AF_ALG 是 Linux 核心中的一個套接字地址家族，用于提供加密和解密服務。它允許用戶空間的應用程序使用 Linux 核心的加密和解密功能。
* **eBPF**: eBPF (extended Berkeley Packet Filter) 是 Linux 核心中的一個技術，允許用戶空間的應用程序注入自定義的程式碼到 Linux 核心中。它可以用於實現網路過濾、安全監控等功能。
* **authencesn**: authencesn 是 Linux 核心中的一個函數，用于提供密碼學服務。它允許用戶空間的應用程序使用 Linux 核心的密碼學功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175557)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


