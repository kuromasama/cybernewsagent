---
layout: post
title:  "Hackers breach TrueConf to trojanize client installers with backdoors"
date:   2026-08-08 18:25:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Head Mare 集團對 TrueConf 視訊會議伺服器的利用：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `TrueConf`, `PhantomCore`, `PhantomGraph`, `Web Shell`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TrueConf 視訊會議伺服器的漏洞（KLCERT-26-057 和 KLCERT-26-058）允許攻擊者在伺服器上執行任意代碼，進而替換客戶端安裝程式並部署後門。
* **攻擊流程圖解**:
  1. 攻擊者連接到 TrueConf 伺服器的 TCP 端口 4307。
  2. 利用 KLCERT-26-057 漏洞在 TrueConf 的隔離環境中執行惡意腳本。
  3. 逃離沙盒並在底層作業系統上執行命令（KLCERT-26-058）。
  4. 提升權限至 NT AUTHORITY\SYSTEM。
  5. 替換 `\public\js\locale.php` 檔案以獲得持續的遠端存取權。
* **受影響元件**: TrueConf Server 5.3.x 之前版本、5.4.x 之前版本、5.5.x 之前版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要存取 TrueConf 伺服器的 TCP 端口 4307。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      payload = {
        'command': 'exec',
        'args': ['malicious_script.py']
      }
    
    ```
  *範例指令*: 使用 `curl` 發送惡意請求

```

bash
  curl -X POST \
  http://trueconf-server:4307 \
  -H 'Content-Type: application/json' \
  -d '{"command": "exec", "args": ["malicious_script.py"]}'

```
* **繞過技術**: 可能使用 WAF 繞過技巧，如使用編碼或混淆來隱藏惡意請求。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `malicious_script.py` 的 SHA256 雜湊值 |
| IP | TrueConf 伺服器的 IP 地址 |
| Domain | TrueConf 伺服器的網域名稱 |
| File Path | `\public\js\locale.php` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule TrueConf_Malicious_Payload {
        meta:
          description = "偵測 TrueConf 惡意 payload"
          author = "Your Name"
        strings:
          $payload = { 28 29 30 31 32 33 34 35 36 37 }
        condition:
          $payload at 0
      }
    
    ```
  或者是使用 SIEM 查詢語法（Splunk/Elastic）進行偵測。
* **緩解措施**: 更新 TrueConf 伺服器至最新版本（5.3.9、5.4.9 或 5.5.5），並設定適當的防火牆規則以限制存取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TrueConf**: 一種視訊會議軟體，尤其在俄羅斯企業和政府部門中被廣泛使用。
* **PhantomCore**: 一種後門軟體，允許攻擊者遠端存取和控制受感染的系統。
* **PhantomGraph**: 一種後門軟體，允許攻擊者遠端存取和控制受感染的系統，並可以接受命令和返回結果。
* **Web Shell**: 一種允許攻擊者遠端存取和控制受感染的系統的網頁介面。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/)
- [MITRE ATT&CK](https://attack.mitre.org/) 編號：T1190（Remote Access Tools）和 T1204（User Execution）


