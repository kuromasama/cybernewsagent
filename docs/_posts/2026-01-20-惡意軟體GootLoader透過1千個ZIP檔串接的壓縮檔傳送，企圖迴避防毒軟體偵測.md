---
layout: post
title:  "惡意軟體GootLoader透過1千個ZIP檔串接的壓縮檔傳送，企圖迴避防毒軟體偵測"
date:   2026-01-20 06:27:29 +0000
categories: [security]
severity: critical
---

# 🚨 ZIP 檔案串接技術：解析與防禦繞過

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ZIP Concatenation, Hashbusting, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ZIP 檔案串接技術是通過將多個 ZIP 檔案串接成單一檔案，利用不同解壓縮工具解析壓縮檔的方式存在差異，使得壓縮檔裡存放的惡意內容不易被察覺。
* **攻擊流程圖解**:
  1. 使用者下載 ZIP 檔案
  2. ZIP 檔案被解壓縮
  3. 惡意內容被執行
* **受影響元件**: Windows 操作系統，尤其是 Windows 檔案總管（File Explorer）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要下載和解壓縮 ZIP 檔案
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import os
      import subprocess
    
      # 下載和解壓縮 ZIP 檔案
      zip_file = "example.zip"
      subprocess.run(["powershell", "-Command", f"Expand-Archive -Path {zip_file} -DestinationPath ."])
    
      # 執行惡意內容
      malicious_file = "malicious.js"
      subprocess.run(["powershell", "-Command", f"Invoke-Expression -Command {malicious_file}"])
    
    ```
* **繞過技術**: 使用 ZIP 檔案串接技術和 Hashbusting 來繞過偵測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Users\example\Downloads\example.zip |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule zip_concatenation {
        meta:
          description = "Detect ZIP file concatenation"
          author = "Example"
        strings:
          $zip_header = { 0x50 0x4b 0x03 0x04 }
        condition:
          $zip_header at 0
      }
    
    ```
* **緩解措施**:
  + 將 Windows 檔案總管（File Explorer）的預設設定修改為使用記事本（Notepad）開啟 JS 和 JSE 檔案
  + 限制 WScript 和 CScript 的功能
  + 封鎖執行從網際網路下載的內容

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ZIP Concatenation (ZIP 檔案串接)**: 想像多個 ZIP 檔案被串接成單一檔案。技術上是指將多個 ZIP 檔案的內容串接成單一檔案，使得壓縮檔裡存放的惡意內容不易被察覺。
* **Hashbusting (雜湊破解)**: 想像攻擊者嘗試破解雜湊值。技術上是指攻擊者嘗試生成多個不同的雜湊值，使得防禦者難以偵測和緩解攻擊。
* **Deserialization (反序列化)**: 想像數據被還原成原始格式。技術上是指將序列化的數據還原成原始格式，可能導致安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173475)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


