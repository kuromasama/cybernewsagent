---
layout: post
title:  "Instructure hacker claims data theft from 8,800 schools, universities"
date:   2026-05-06 02:09:59 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Instructure 資料洩露事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 資料洩露 (Data Leak)
> * **關鍵技術**: Canvas 資料匯出功能、DAP 查詢、Provisioning Reports、User APIs

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Instructure 的 Canvas 平台中，資料匯出功能沒有適當的存取控制和驗證，導致攻擊者可以利用 DAP 查詢、Provisioning Reports 和 User APIs 匯出大量敏感資料。
* **攻擊流程圖解**: 
  1. 攻擊者獲得 Canvas 平台的存取權限
  2. 攻擊者使用 DAP 查詢、Provisioning Reports 和 User APIs 匯出資料
  3. 攻擊者下載和分析匯出的資料
* **受影響元件**: Instructure Canvas 平台，版本號未指定

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Canvas 平台的存取權限
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 DAP 查詢參數
    dap_query = {
        "query": "SELECT * FROM users",
        "limit": 10000
    }
    
    # 定義 Provisioning Reports 參數
    provisioning_report = {
        "report_type": "user",
        "format": "csv"
    }
    
    # 定義 User APIs 參數
    user_api = {
        "endpoint": "/api/v1/users",
        "params": {
            "per_page": 10000
        }
    }
    
    # 發送 DAP 查詢請求
    response = requests.post("https://example.com/api/v1/dap", json=dap_query)
    
    # 發送 Provisioning Reports 請求
    response = requests.get("https://example.com/api/v1/reports", params=provisioning_report)
    
    # 發送 User APIs 請求
    response = requests.get("https://example.com/api/v1/users", params=user_api)
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術，例如使用代理伺服器或 VPN 來隱藏 IP 地址

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /api/v1/dap |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Instructure_Canvas_Data_Leak {
      meta:
        description = "Instructure Canvas 資料洩露事件"
        author = "Your Name"
      strings:
        $dap_query = "SELECT * FROM users"
        $provisioning_report = "report_type=user&format=csv"
        $user_api = "/api/v1/users"
      condition:
        any of them
    }
    
    ```
* **緩解措施**: 
  + 更新 Instructure Canvas 平台到最新版本
  + 啟用存取控制和驗證機制
  + 監控和分析 DAP 查詢、Provisioning Reports 和 User APIs 的請求

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DAP (Data Access Protocol)**: 一種用於存取和管理資料的協議
* **Provisioning Reports**: 一種用於生成和下載報告的功能
* **User APIs**: 一種用於存取和管理用戶資料的 API

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/instructure-hacker-claims-data-theft-from-8-800-schools-universities/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


