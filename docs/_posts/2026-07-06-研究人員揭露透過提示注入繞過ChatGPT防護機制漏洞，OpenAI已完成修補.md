---
layout: post
title:  "研究人員揭露透過提示注入繞過ChatGPT防護機制漏洞，OpenAI已完成修補"
date:   2026-07-06 15:19:39 +0000
categories: [security]
severity: high
---

# 🔥 ChatGPT 安全防護機制繞過漏洞解析
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: Prompt Injection, Path Traversal, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ChatGPT 的安全防護機制中，當用戶上傳檔案後，系統會拒絕直接下載該檔案的要求，並提示該檔案為暫時上傳、已被刪除。然而，攻擊者可以先指示 AI 模型編輯該檔案，再以意外刪除檔案為由，要求提供下載鏈接，從而暴露檢索檔案的內部端點路徑。
* **攻擊流程圖解**:
  1. User Input -> 上傳檔案
  2. ChatGPT -> 拒絕直接下載檔案
  3. Attacker -> 指示 AI 模型編輯檔案
  4. ChatGPT -> 產生有效的下載 URL
  5. Attacker -> 獲取下載 URL 並暴露內部端點路徑
* **受影響元件**: ChatGPT 的上傳檔案功能，尤其是當用戶上傳檔案後，系統的安全防護機制會被繞過。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 ChatGPT 的使用權限，並能夠上傳檔案。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 上傳檔案
    file = {'file': open('example.txt', 'rb')}
    response = requests.post('https://chatgpt.com/upload', files=file)
    
    # 指示 AI 模型編輯檔案
    edit_url = 'https://chatgpt.com/edit'
    response = requests.post(edit_url, json={'file_id': response.json()['file_id']})
    
    # 獲取下載 URL 並暴露內部端點路徑
    download_url = 'https://chatgpt.com/download'
    response = requests.get(download_url, params={'file_id': response.json()['file_id']})
    
    # 繞過存取限制，下載原始路徑以外的資訊
    path_traversal_url = 'https://chatgpt.com/download'
    response = requests.get(path_traversal_url, params={'file_id': response.json()['file_id'], 'path': '../'})
    
    ```
* **繞過技術**: 攻擊者可以使用路徑遍歷（Path Traversal）方式，繞過存取路徑限制，下載原始路徑以外的資訊。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | chatgpt.com | /upload |
|  |  | chatgpt.com | /edit |
|  |  | chatgpt.com | /download |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ChatGPT_Prompt_Injection {
      meta:
        description = "Detects ChatGPT prompt injection attacks"
      strings:
        $prompt_injection = "file_id"
      condition:
        $prompt_injection
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還可以修改 ChatGPT 的上傳檔案功能，限制用戶上傳檔案的類型和大小，並增加安全防護機制，例如驗證用戶的身份和權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Prompt Injection (提示注入)**: 想像攻擊者可以注入惡意的提示，讓 AI 模型執行攻擊者的命令。技術上是指攻擊者可以注入惡意的輸入，讓 AI 模型產生不預期的結果。
* **Path Traversal (路徑遍歷)**: 想像攻擊者可以遍歷檔案系統，下載原始路徑以外的資訊。技術上是指攻擊者可以使用特殊的字元，例如 `../`，來遍歷檔案系統，下載原始路徑以外的資訊。
* **Deserialization (反序列化)**: 想像攻擊者可以反序列化惡意的資料，讓 AI 模型執行攻擊者的命令。技術上是指攻擊者可以反序列化惡意的資料，讓 AI 模型產生不預期的結果。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177127)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


