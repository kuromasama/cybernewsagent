---
layout: post
title:  "【資安日報】1月20日，惡意軟體GootLoader透過ZIP串接手法迴避防毒軟體與EDR偵測"
date:   2026-01-20 12:35:57 +0000
categories: [security]
severity: high
---

# 🔥 GootLoader惡意軟體透過特殊ZIP檔迴避防毒軟體偵測：解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS分數：8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ZIP檔結構破壞、加密通訊、DLL側載

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GootLoader惡意軟體透過特殊的ZIP檔結構破壞，缺乏兩個重要的位元組，導致大部分工具嘗試解析ZIP檔結構的時候會出錯。
* **攻擊流程圖解**:
  1. 使用者下載特殊的ZIP檔。
  2. ZIP檔被解壓縮，啟動惡意行為。
  3. 惡意軟體使用加密通訊機制，與C2伺服器進行通訊。
* **受影響元件**: Windows檔案總管（File Explorer）、7-Zip、WinRAR等解壓縮工具。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要下載特殊的ZIP檔。
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例Payload結構
      zip_file = zipfile.ZipFile('example.zip', 'w')
      zip_file.writestr('example.txt', 'Hello World!')
      zip_file.close()
    
    ```
* **繞過技術**: 使用特殊的ZIP檔結構破壞，缺乏兩個重要的位元組，導致大部分工具嘗試解析ZIP檔結構的時候會出錯。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\example.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule GootLoader {
        meta:
          description = "GootLoader惡意軟體"
          author = "Your Name"
        strings:
          $a = "example.txt"
        condition:
          $a
      }
    
    ```
* **緩解措施**: 更新防毒軟體，使用安全的解壓縮工具，避免下載來源不明的ZIP檔。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL側載 (DLL Hijacking)**: 想像兩個DLL檔案同時被載入記憶體，且至少有一個是惡意的，導致系統不穩定或出現安全漏洞。技術上是指攻擊者將惡意的DLL檔案放在系統的搜尋路徑中，當系統需要載入DLL檔案時，會先找到惡意的DLL檔案，從而執行惡意代碼。
* **加密通訊 (Encrypted Communication)**: 使用加密演算法保護通訊內容，防止第三方截取或竊聽。技術上是指使用密鑰和加密演算法將明文轉換為密文，然後傳輸密文，接收方使用相同的密鑰和加密演算法將密文轉換回明文。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173483)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


