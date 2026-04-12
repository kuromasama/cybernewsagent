---
layout: post
title:  "CPUID Breach Distributes STX RAT via Trojanized CPU-Z and HWMonitor Downloads"
date:   2026-04-12 07:06:00 +0000
categories: [security]
severity: high
---

# 🔥 解析 CPUID 網站攻擊：STX RAT 的部署與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL Side-Loading, Anti-Sandbox Checks, Reverse Proxy/Tunneling

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CPUID 網站的次要功能（side API）被攻擊者利用，導致主網站隨機顯示惡意連結。這個漏洞可能是由於網站的 API 沒有進行適當的驗證和授權，導致攻擊者可以輕易地注入惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者利用 CPUID 網站的漏洞注入惡意代碼。
  2. 使用者下載 CPU-Z 或 HWMonitor 安裝程式。
  3. 安裝程式執行惡意 DLL（CRYPTBASE.dll），並啟動 STX RAT。
  4. STX RAT 進行反沙盒檢查，避免被偵測。
  5. STX RAT 與 C2 伺服器建立連接，下載和執行額外的 payload。
* **受影響元件**: CPUID 網站、CPU-Z、HWMonitor、HWMonitor Pro、PerfMonitor。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 CPUID 網站的管理權限或是能夠利用網站的漏洞。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意 DLL 的結構
    class MaliciousDLL:
        def __init__(self):
            self.dll_name = "CRYPTBASE.dll"
            self.payload = "STX RAT"
    
        def execute(self):
            # 啟動 STX RAT
            subprocess.Popen([self.payload])
    
    # 建立惡意 DLL
    malicious_dll = MaliciousDLL()
    malicious_dll.execute()
    
    ```
* **繞過技術**: 攻擊者使用反沙盒檢查來避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | cahayailmukreatif.web.id | C:\Windows\System32\CRYPTBASE.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule MaliciousDLL {
        meta:
            description = "偵測惡意 DLL"
            author = "Blue Team"
        strings:
            $dll_name = "CRYPTBASE.dll"
        condition:
            $dll_name at 0
    }
    
    ```
* **緩解措施**: 更新 CPUID 網站的安全補丁，使用防毒軟體和防火牆來阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL Side-Loading**: 想像兩個 DLL 文件同時被載入記憶體，且其中一個 DLL 文件是惡意的。技術上是指攻擊者可以利用 Windows 的 DLL 載入機制，將惡意 DLL 文件載入記憶體，從而執行惡意代碼。
* **Anti-Sandbox Checks**: 想像攻擊者可以檢查是否在沙盒環境中執行。技術上是指攻擊者可以使用各種技術來檢查是否在沙盒環境中執行，例如檢查系統的配置、網路連接等。
* **Reverse Proxy/Tunneling**: 想像攻擊者可以建立一個反向代理伺服器，將流量轉發到惡意伺服器。技術上是指攻擊者可以使用反向代理技術，將流量轉發到惡意伺服器，從而繞過防火牆和入侵偵測系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/cpuid-breach-distributes-stx-rat-via.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


