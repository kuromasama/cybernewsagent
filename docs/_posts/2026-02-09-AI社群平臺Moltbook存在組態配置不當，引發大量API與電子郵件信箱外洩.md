---
layout: post
title:  "AI社群平臺Moltbook存在組態配置不當，引發大量API與電子郵件信箱外洩"
date:   2026-02-09 06:57:49 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Moltbook AI 代理資料庫配置不當漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 未經授權的資料庫存取與寫入
> * **關鍵技術**: `Supabase` 資料庫配置不當、`API 金鑰` 曝露、`JavaScript` 客戶端驗證繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Moltbook 的 Supabase 資料庫配置不當，導致 API 金鑰曝露，允許未經授權的存取與寫入。
* **攻擊流程圖解**:
  1. 攻擊者瀏覽 Moltbook 網站，檢視網頁載入的 JavaScript 元件。
  2. JavaScript 元件中包含 Supabase 資料庫的 API 金鑰。
  3. 攻擊者使用 API 金鑰存取 Supabase 資料庫，進行任意讀寫。
* **受影響元件**: Moltbook 網站、Supabase 資料庫

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路存取、JavaScript 執行環境
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 範例 Payload
    const apiToken = 'YOUR_API_TOKEN';
    const supabaseUrl = 'https://YOUR_SUPABASE_URL';
    
    fetch(supabaseUrl + '/api/v1/table', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + apiToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        'table': 'YOUR_TABLE_NAME',
        'data': 'YOUR_DATA'
      })
    })
    
    ```
* **繞過技術**: 使用 JavaScript 客戶端驗證繞過，直接存取 Supabase 資料庫

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `YOUR_HASH_VALUE` |
| IP | `YOUR_IP_ADDRESS` |
| Domain | `YOUR_DOMAIN_NAME` |
| File Path | `YOUR_FILE_PATH` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Moltbook_Supabase_Vulnerability {
      meta:
        description = "Moltbook Supabase 資料庫配置不當漏洞"
      strings:
        $api_token = "YOUR_API_TOKEN"
      condition:
        $api_token in (all of them)
    }
    
    ```
* **緩解措施**: 更新 Supabase 資料庫配置，啟用 API 金鑰驗證，限制存取權限

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supabase**: 一種基於 PostgreSQL 的雲端資料庫平台。
* **API 金鑰**: 一種用於驗證 API 請求的金鑰。
* **JavaScript 客戶端驗證繞過**: 一種攻擊技術，利用 JavaScript 客戶端驗證的漏洞，直接存取伺服器端的資源。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173846)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


