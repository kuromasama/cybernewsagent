---
layout: post
title:  "Azure Cosmos DB Flaw Exposed Platform-Wide Key That Could Access Any Database"
date:   2026-07-30 19:13:44 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Azure Cosmos DB Gremlin 查詢沙盒逃逸漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: .NET Reflection, Arbitrary Code Execution, Signing Key Escalation

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Azure Cosmos DB 的 Gremlin 查詢引擎將 Gremlin 查詢轉換為 .NET 代碼並在受限制的環境中執行。然而，這個限制並沒有考慮到 .NET 反射（Reflection），使得攻擊者可以建立文件讀寫原語並達到任意代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者提交精心設計的 Gremlin 查詢到受其控制的 Gremlin 數據庫。
  2. 查詢被轉換為 .NET 代碼並在受限制的環境中執行。
  3. 攻擊者利用 .NET 反射建立文件讀寫原語。
  4. 攻擊者利用文件讀寫原語讀取平台範圍的簽署密鑰和區域帳戶目錄。
  5. 攻擊者利用簽署密鑰和區域帳戶目錄找到目標帳戶並检索其主要帳戶金鑰。
* **受影響元件**: Azure Cosmos DB 的 Gremlin 查詢引擎，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制一個 Gremlin 數據庫和相關的憑證。
* **Payload 建構邏輯**:

    ```
    
    csharp
      // 示例 Gremlin 查詢
      g.V().has('name', 'example').out('knows')
    
    ```
  攻擊者需要提交這個查詢到受其控制的 Gremlin 數據庫，並利用 .NET 反射建立文件讀寫原語。
* **繞過技術**: 攻擊者可以利用簽署密鑰和區域帳戶目錄找到目標帳戶並检索其主要帳戶金鑰，從而繞過安全限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 未指定 |
| Domain | 未指定 |
| File Path | 未指定 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Azure_Cosmos_DB_Gremlin_Sandbox_Escape {
        meta:
          description = "Azure Cosmos DB Gremlin Sandbox Escape"
          author = "Your Name"
        strings:
          $gremlin_query = "g.V().has('name', 'example').out('knows')"
        condition:
          $gremlin_query
      }
    
    ```
* **緩解措施**: 更新 Azure Cosmos DB 到最新版本，並確保 Gremlin 查詢引擎受到適當的限制和監控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **.NET Reflection**: .NET 反射是一種技術，允許程式在執行時檢查和修改其他程式的結構和行為。
* **Arbitrary Code Execution**: 任意代碼執行是一種安全漏洞，允許攻擊者在目標系統上執行任意代碼。
* **Signing Key Escalation**: 簽署密鑰升級是一種安全漏洞，允許攻擊者升級其權限並存取敏感數據。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


