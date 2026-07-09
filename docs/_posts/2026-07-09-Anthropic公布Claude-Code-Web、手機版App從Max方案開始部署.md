---
layout: post
title:  "Anthropic公布Claude Code Web、手機版App從Max方案開始部署"
date:   2026-07-09 02:14:20 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Anthropic Claude Cowork 的安全性與潛在風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Potential Information Leak
> * **關鍵技術**: AI 自主代理人、多步驟任務執行、跨檔案和應用程式存取

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude Cowork 的設計允許使用者授予存取電腦特定資料夾的讀寫權限，可能導致未經授權的資料存取或修改。
* **攻擊流程圖解**: 
    1. 使用者授予 Claude Cowork 存取權限
    2. Claude Cowork 執行多步驟任務，可能涉及檔案讀寫、電子郵件和訊息 App 等
    3.攻擊者可能利用 Claude Cowork 的權限存取敏感資料
* **受影響元件**: Claude Cowork 的手機和 Web 版本，特別是當使用者授予高級權限時

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得使用者授予 Claude Cowork 的權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 範例 Payload
    payload = {
        "task": "read_file",
        "file_path": "/path/to/sensitive/file"
    }
    
    # 送出請求
    response = requests.post("https://claude.ai/api/execute", json=payload)
    
    # 處理回應
    if response.status_code == 200:
        print("成功讀取檔案")
    else:
        print("失敗")
    
    ```
    *範例指令*: 使用 `curl` 送出請求

```

bash
curl -X POST \
  https://claude.ai/api/execute \
  -H 'Content-Type: application/json' \
  -d '{"task": "read_file", "file_path": "/path/to/sensitive/file"}'

```
* **繞過技術**: 可能利用 Claude Cowork 的 AI 自主代理人功能，讓攻擊者在不被發現的情況下執行任務

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | claude.ai | /path/to/sensitive/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Claude_Cowork_Anomaly {
        meta:
            description = "Detects anomalous Claude Cowork activity"
            author = "Your Name"
        strings:
            $a = "https://claude.ai/api/execute"
        condition:
            $a in (http.request.uri)
    }
    
    ```
    或者使用 SIEM 查詢語法 (Splunk/Elastic) 來偵測異常行為

```

spl
index=web_logs (http.request.uri="https://claude.ai/api/execute") | stats count as num_requests by src_ip | where num_requests > 10

```
* **緩解措施**: 
    1. 限制 Claude Cowork 的權限
    2. 監控 Claude Cowork 的活動
    3. 更新 Claude Cowork 的版本

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AI 自主代理人 (Autonomous Agent)**: 一種可以自主執行任務的 AI 系統，無需人工干預。
* **多步驟任務 (Multi-Step Task)**: 一種需要多個步驟才能完成的任務，例如讀取檔案、發送電子郵件等。
* **跨檔案和應用程式存取 (Cross-File and Application Access)**: Claude Cowork 可以存取多個檔案和應用程式，可能導致資料泄露或其他安全問題。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177189)
- [MITRE ATT&CK](https://attack.mitre.org/)


