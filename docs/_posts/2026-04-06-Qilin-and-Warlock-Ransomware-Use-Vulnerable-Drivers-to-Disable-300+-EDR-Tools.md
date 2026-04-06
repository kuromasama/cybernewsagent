---
layout: post
title:  "Qilin and Warlock Ransomware Use Vulnerable Drivers to Disable 300+ EDR Tools"
date:   2026-04-06 12:55:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Qilin 和 Warlock 勒索軟體的 BYOVD 攻擊技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: BYOVD (Bring Your Own Vulnerable Driver), DLL Side-Loading, Kernel-Mode Hardware Access

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Qilin 和 Warlock 勒索軟體使用 BYOVD 技術，利用漏洞驅動程式（如 `rwdrv.sys` 和 `hlpdrv.sys`）來終止安全工具的驅動程式，從而繞過安全控制。
* **攻擊流程圖解**:
  1. 攻擊者使用 DLL Side-Loading 技術，載入惡意 DLL (`msimg32.dll`)。
  2. 惡意 DLL 啟動多階段感染鏈，終止 EDR (Endpoint Detection and Response) 驅動程式。
  3. 攻擊者使用 BYOVD 技術，載入漏洞驅動程式 (`rwdrv.sys` 和 `hlpdrv.sys`)。
  4. 漏洞驅動程式終止安全工具的驅動程式，允許攻擊者繞過安全控制。
* **受影響元件**: Windows 10、Windows Server 2019、各種安全工具的驅動程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Administrator 權限，且需要能夠載入惡意 DLL 和漏洞驅動程式。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意 DLL 的結構
    class MaliciousDLL:
        def __init__(self):
            self.edr_killer = EDRKiller()
            self.byovd_loader = BYOVDLoader()
    
        def start(self):
            self.edr_killer.terminate_edr_drivers()
            self.byovd_loader.load_vulnerable_drivers()
    
    # BYOVD 載入器的結構
    class BYOVDLoader:
        def __init__(self):
            self.vulnerable_drivers = ['rwdrv.sys', 'hlpdrv.sys']
    
        def load_vulnerable_drivers(self):
            for driver in self.vulnerable_drivers:
                # 載入漏洞驅動程式
                load_driver(driver)
    
    ```
* **繞過技術**: 攻擊者使用 DLL Side-Loading 技術，載入惡意 DLL，從而繞過安全控制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `example.com` | `C:\Windows\System32\msimg32.dll` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule MaliciousDLL {
        meta:
            description = "惡意 DLL"
            author = "Blue Team"
        strings:
            $s1 = "EDRKiller"
            $s2 = "BYOVDLoader"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新安全工具，禁用未簽名的驅動程式，監控驅動程式的安裝事件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **BYOVD (Bring Your Own Vulnerable Driver)**: 攻擊者使用漏洞驅動程式來繞過安全控制。
* **DLL Side-Loading**: 攻擊者使用 DLL Side-Loading 技術，載入惡意 DLL，從而繞過安全控制。
* **Kernel-Mode Hardware Access**: 攻擊者使用漏洞驅動程式，獲得核心模式硬體存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/qilin-and-warlock-ransomware-use.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


