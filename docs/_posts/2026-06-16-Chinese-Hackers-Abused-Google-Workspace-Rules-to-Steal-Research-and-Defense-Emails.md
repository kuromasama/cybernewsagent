---
layout: post
title:  "Chinese Hackers Abused Google Workspace Rules to Steal Research and Defense Emails"
date:   2026-06-16 03:25:13 +0000
categories: [security]
severity: critical
---

# 🚨 解析中國駭客利用 Google Workspace 規則進行敏感研究和國防郵件竊取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Unauthenticated Remote Code Execution (RCE) 和敏感信息竊取
> * **關鍵技術**: REDCap漏洞利用、Google Workspace規則繞過、內網橫向移動

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: REDCap是一個開源的研究數據收集平台，駭客利用其漏洞（未指定CVE）獲得初始訪問權限。隨後，駭客部署了一個自定義的木馬程式（INFINITERED），該程式劫持了REDCap的升級過程，竊取用戶名和密碼，並作為一個後門，通過HTTP Cookie接收命令。
* **攻擊流程圖解**:
  1. 駭客利用REDCap漏洞獲得初始訪問權限。
  2. 部署INFINITERED木馬程式。
  3.竊取用戶名和密碼。
  4. 獲得域管理員權限。
  5. 創建Google Workspace規則，將敏感郵件複製到駭客控制的郵箱。
* **受影響元件**: REDCap版本未指定，Google Workspace。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有REDCap的訪問權限和Google Workspace的管理員權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例Payload
      import requests
    
      # REDCap漏洞利用
      url = "https://example.com/REDCap/vulnerability"
      payload = {"username": "admin", "password": "password"}
      response = requests.post(url, data=payload)
    
      # 部署INFINITERED木馬程式
      url = "https://example.com/REDCap/upload"
      payload = {"file": "INFINITERED.exe"}
      response = requests.post(url, files=payload)
    
      #竊取用戶名和密碼
      url = "https://example.com/REDCap/login"
      payload = {"username": "admin", "password": "password"}
      response = requests.post(url, data=payload)
    
      # 獲得域管理員權限
      url = "https://example.com/REDCap/admin"
      payload = {"username": "admin", "password": "password"}
      response = requests.post(url, data=payload)
    
      # 創建Google Workspace規則
      url = "https://example.com/GoogleWorkspace/rules"
      payload = {"rule": "copy email to attacker's inbox"}
      response = requests.post(url, data=payload)
    
    ```
* **繞過技術**: 利用Google Workspace規則繞過傳統的郵件安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.1 | example.com | /REDCap/vulnerability |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule REDCap_Vulnerability {
        meta:
          description = "REDCap漏洞利用"
          author = "Your Name"
        strings:
          $a = "REDCap/vulnerability"
        condition:
          $a
      }
    
    ```
* **緩解措施**:
  1. 更新REDCap版本。
  2. 刪除INFINITERED木馬程式。
  3. 變更用戶名和密碼。
  4. 刪除Google Workspace規則。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **REDCap**: 一個開源的研究數據收集平台。
* **INFINITERED**: 一個自定義的木馬程式，劫持了REDCap的升級過程，竊取用戶名和密碼，並作為一個後門，通過HTTP Cookie接收命令。
* **Google Workspace規則**: 一種用於管理Google Workspace郵件的規則，可以用於複製或轉發郵件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/chinese-hackers-abused-google-workspace.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


