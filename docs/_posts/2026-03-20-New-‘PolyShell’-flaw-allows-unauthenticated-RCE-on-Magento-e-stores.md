---
layout: post
title:  "New ‘PolyShell’ flaw allows unauthenticated RCE on Magento e-stores"
date:   2026-03-20 01:26:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 PolyShell 漏洞：Magento 電子商務平台的遠程代碼執行風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `REST API`, `File Upload`, `Polyglot File`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: 漏洞源於 Magento 的 REST API 接受檔案上傳作為自訂選項的一部分。當產品選項類型為 `file` 時，Magento 會處理一個包含 base64 編碼檔案資料、MIME 類型和檔案名稱的 `file_info` 物件。該檔案會被寫入 `pub/media/custom_options/quote/` 目錄。
* **攻擊流程圖解**:
  1. 攻擊者上傳一個 polyglot 檔案（可作為圖像和腳本）。
  2. Magento 處理檔案上傳並將其寫入目錄。
  3. 攻擊者利用檔案上傳漏洞，實現遠程代碼執行或儲存型 XSS。
* **受影響元件**: 所有 Magento Open Source 和 Adobe Commerce 穩定版本 2 安裝。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 無需驗證即可上傳檔案。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 payload
      file_info = {
        'file_data': 'base64_encoded_file_data',
        'mime_type': 'image/jpeg',
        'filename': 'example.jpg'
      }
    
    ```
 

```

bash
  # 使用 curl 上傳檔案
  curl -X POST \
    http://example.com/rest/V1/customOptions/quote \
    -H 'Content-Type: application/json' \
    -d '{"file_info": {"file_data": "base64_encoded_file_data", "mime_type": "image/jpeg", "filename": "example.jpg"}}'

```
* **繞過技術**: 可能使用 WAF 繞過技巧，例如使用不同的 HTTP 方法或編碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | `pub/media/custom_options/quote/` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule PolyShell_Detection {
        meta:
          description = "Detects PolyShell vulnerability"
        strings:
          $file_info = "{ \"file_data\": \"base64_encoded_file_data\" }"
        condition:
          $file_info
      }
    
    ```
 

```

snort
  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PolyShell Detection"; content:"file_info"; sid:1000001;)

```
* **緩解措施**:
  1. 限制存取 `pub/media/custom_options/` 目錄。
  2. 驗證 nginx 或 Apache 規則是否防止存取。
  3. 掃描商店以查找上傳的 shell、後門或其他惡意軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Polyglot File (多語言檔案)**: 一種可以作為多種檔案類型（例如圖像和腳本）的檔案。這種檔案可以用於繞過安全檢查。
* **REST API (RESTful API)**: 一種基於 HTTP 的 API，使用 JSON 或 XML 等格式傳輸資料。
* **File Upload (檔案上傳)**: 一種允許用戶上傳檔案到伺服器的功能。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.bleepingcomputer.com/news/security/new-polyshell-flaw-allows-unauthenticated-rce-on-magento-e-stores/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


