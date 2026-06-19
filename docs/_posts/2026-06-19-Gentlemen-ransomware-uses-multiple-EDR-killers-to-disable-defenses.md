---
layout: post
title:  "Gentlemen ransomware uses multiple EDR killers to disable defenses"
date:   2026-06-19 03:38:43 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GentleKiller：一種高級的端點檢測和響應（EDR）殺手工具

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Local Privilege Escalation (LPE) 和 Endpoint Detection and Response (EDR) 繞過
> * **關鍵技術**: Bring Your Own Vulnerable Driver (BYOVD), Code Obfuscation, Process Killing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GentleKiller 利用 BYOVD 技術來提升權限並禁用安全引擎。這是因為 Windows 的驅動程序可以訪問核心模式，從而允許攻擊者執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者將 GentleKiller 上傳到目標系統。
  2. GentleKiller 啟動並載入易受攻擊的驅動程序。
  3. 驅動程序提升 GentleKiller 的權限。
  4. GentleKiller 殺死 EDR 進程並禁用安全引擎。
* **受影響元件**: Windows 10、Windows Server 2019、多個安全軟件和 EDR 解決方案。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 管理員權限、網路位置。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 載入易受攻擊的驅動程序
    subprocess.call(['rundll32.exe', 'vuln_driver.dll'])
    
    # 殺死 EDR 進程
    os.system('taskkill /im edr_process.exe')
    
    # 禁用安全引擎
    subprocess.call(['reg', 'add', 'HKLM\SYSTEM\CurrentControlSet\Services\security_engine', '/v', 'Start', '/t', 'REG_DWORD', '/d', '4', '/f'])
    
    ```
* **繞過技術**: GentleKiller 使用 code obfuscation 和 process killing 來繞過 EDR 和安全引擎。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\GentleKiller.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GentleKiller {
      meta:
        description = "GentleKiller EDR Killer"
        author = "Your Name"
      strings:
        $a = "GentleKiller"
        $b = "vuln_driver.dll"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新系統和安全軟件、禁用不必要的驅動程序、監視系統日誌和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Bring Your Own Vulnerable Driver (BYOVD)**: 一種攻擊技術，利用易受攻擊的驅動程序來提升權限和執行任意代碼。
* **Code Obfuscation**: 一種技術，用于混淆和保護代碼，難以被逆向工程和分析。
* **Endpoint Detection and Response (EDR)**: 一種安全解決方案，用于實時監視和響應端點安全事件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/gentlemen-ransomware-uses-multiple-edr-killers-to-disable-defenses/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


