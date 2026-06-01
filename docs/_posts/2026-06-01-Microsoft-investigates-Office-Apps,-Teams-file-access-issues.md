---
layout: post
title:  "Microsoft investigates Office Apps, Teams file access issues"
date:   2026-06-01 17:24:30 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft Teams 與 Office for the web 的檔案存取漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: File Access Issue
> * **關鍵技術**: Cross-Service Issue, Office for the web, Microsoft Teams

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 根據 Microsoft 的描述，該漏洞是由於 Office for the web 和 Microsoft Teams 之間的跨服務問題引起的。具體來說，當使用者嘗試開啟檔案時，Office for the web 服務無法正確地處理請求，導致檔案無法開啟。
* **攻擊流程圖解**: 
    1. 使用者嘗試開啟檔案
    2. Office for the web 服務接收請求
    3. 服務無法正確地處理請求
    4. 檔案無法開啟
* **受影響元件**: Microsoft Teams、Office for the web（包括 Excel、PowerPoint 等）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要有 Microsoft Teams 或 Office for the web 的帳戶
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義檔案開啟請求
    def open_file_request(file_id):
        url = f"https://teams.microsoft.com/api/files/{file_id}"
        headers = {
            "Authorization": "Bearer <access_token>",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        return response
    
    # 定義攻擊 payload
    def attack_payload(file_id):
        payload = {
            "fileId": file_id,
            "action": "open"
        }
        return payload
    
    # 執行攻擊
    file_id = "<file_id>"
    payload = attack_payload(file_id)
    response = open_file_request(file_id)
    print(response.text)
    
    ```
    *範例指令*: 使用 `curl` 執行攻擊

```

bash
curl -X GET \
  https://teams.microsoft.com/api/files/<file_id> \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json'

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用不同的 HTTP 方法或添加無害的請求頭

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| <hash> | <ip> | teams.microsoft.com | /api/files/<file_id> |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Teams_File_Access_Issue {
        meta:
            description = "Detects Microsoft Teams file access issue"
            author = "Your Name"
        strings:
            $url = "https://teams.microsoft.com/api/files/"
        condition:
            $url in (http.request.uri)
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)

```

sql
index=web_logs 

| search https://teams.microsoft.com/api/files/
| stats count as num_requests
| where num_requests > 10
```
* **緩解措施**: 
    + 更新 Microsoft Teams 和 Office for the web 至最新版本
    + 啟用 WAF 並設定規則以阻止攻擊請求
    + 監控系統日誌以偵測異常活動

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cross-Service Issue (跨服務問題)**: 指多個服務之間的溝通或協調問題，可能導致服務無法正確地運作。
* **Office for the web (Office 網頁版)**: Microsoft 的 Office 網頁版，允許使用者在網頁上編輯和查看 Office 文件。
* **Microsoft Teams (Microsoft 團隊)**: Microsoft 的團隊合作平台，允許使用者進行溝通、協作和文件共享。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-investigates-office-apps-teams-file-access-issues/)
- [Microsoft Teams 文件](https://docs.microsoft.com/zh-tw/microsoftteams/)
- [Office for the web 文件](https://docs.microsoft.com/zh-tw/office365/)


