---
layout: post
title:  "ExifTool修補macOS指令注入漏洞，未更新可能導致惡意圖片metadata觸發執行任意指令"
date:   2026-05-27 09:34:55 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ExifTool 的 OS Command Injection 漏洞：CVE-2026-3102
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `OS Command Injection`, `ExifTool`, `PNG檔案處理`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ExifTool 在處理 PNG 檔案的 metadata 時，沒有正確地檢查 `DateTimeOriginal` 欄位的內容，導致攻擊者可以透過竄改此欄位內容，將惡意 shell 指令嵌入，從而實現 OS Command Injection。
* **攻擊流程圖解**: 
  1. 攻擊者竄改 PNG 檔案的 `DateTimeOriginal` 欄位內容，嵌入惡意 shell 指令。
  2. 受害者使用 ExifTool 處理該 PNG 檔案。
  3. ExifTool 執行惡意 shell 指令，導致任意代碼執行。
* **受影響元件**: ExifTool 13.49 以前的版本，尤其是在 macOS 環境下。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有能力竄改 PNG 檔案的 metadata，並且受害者需要使用 ExifTool 處理該檔案。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      payload = "echo 'Hello, World!' > /tmp/test.txt"
      # 將 payload 嵌入 PNG 檔案的 DateTimeOriginal 欄位
      png_file = "example.png"
      exiftool = "exiftool"
      command = f"{exiftool} -DateTimeOriginal='{payload}' {png_file}"
    
    ```
  *範例指令*:

```

bash
  curl -X POST -F "file=@example.png" http://example.com/upload

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏惡意 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/test.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ExifTool_OS_Command_Injection {
        meta:
          description = "Detect ExifTool OS Command Injection"
          author = "Your Name"
        strings:
          $a = "exiftool" ascii
          $b = "-DateTimeOriginal=" ascii
        condition:
          $a and $b
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
  index=security sourcetype=exiftool | search "DateTimeOriginal" | stats count as num by src_ip

```
* **緩解措施**: 更新 ExifTool 至 13.50 版本或以上，或者修改 ExifTool 的配置文件以禁用 `DateTimeOriginal` 欄位的處理。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OS Command Injection (操作系統命令注入)**: 想像你可以在別人的電腦上執行任意命令。技術上是指攻擊者可以透過某些漏洞或弱點，將惡意命令注入到操作系統中，從而實現任意代碼執行。
* **ExifTool**: 一個開源的工具，用于處理圖片檔案的 metadata。
* **PNG檔案處理**: PNG (Portable Network Graphics) 是一種圖片檔案格式，ExifTool 可以處理 PNG 檔案的 metadata。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176164)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


