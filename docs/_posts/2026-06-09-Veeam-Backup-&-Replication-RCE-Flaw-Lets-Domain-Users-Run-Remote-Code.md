---
layout: post
title:  "Veeam Backup & Replication RCE Flaw Lets Domain Users Run Remote Code"
date:   2026-06-09 19:59:37 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Veeam Backup & Replication 遠端代碼執行漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.4)
> * **受駭指標**: 遠端代碼執行 (RCE)
> * **關鍵技術**: 認證使用者、備份伺服器、遠端代碼執行

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Veeam Backup & Replication 軟體中的一個認證使用者可以遠端執行代碼的漏洞。這個漏洞可能是由於軟體中某個函數沒有正確檢查使用者的權限，或者是軟體中存在某個未經檢查的緩衝區。
* **攻擊流程圖解**: 
  1. 攻擊者先登入 Veeam Backup & Replication 伺服器，獲得認證使用者的權限。
  2. 攻擊者利用漏洞在伺服器上執行任意代碼，可能是通過發送特定的 HTTP 請求或使用某個工具。
  3. 代碼執行後，攻擊者可以控制伺服器，進行資料竊取、修改或其他惡意行為。
* **受影響元件**: Veeam Backup & Replication 12.3.2.4465 和所有早期版本的 12 建置版。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Veeam Backup & Replication 伺服器的認證使用者權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義攻擊的 URL 和資料
    url = "https://example.com/veeam/backup"
    data = {"command": "execute", "code": "malicious_code"}
    
    # 發送 HTTP 請求
    response = requests.post(url, json=data)
    
    # 判斷攻擊是否成功
    if response.status_code == 200:
        print("攻擊成功")
    else:
        print("攻擊失敗")
    
    ```
  *範例指令*: 使用 `curl` 工具發送 HTTP 請求：

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"command": "execute", "code": "malicious_code"}' https://example.com/veeam/backup

```
* **繞過技術**: 如果伺服器上安裝了 WAF 或 EDR，攻擊者可能需要使用某些技巧來繞過這些安全措施，例如使用加密或編碼的 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.168.1.100 |
| Domain | example.com |
| File Path | /veeam/backup |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Veeam_Backup_Exploit {
      meta:
        description = "Veeam Backup & Replication 遠端代碼執行漏洞"
        author = "Your Name"
      strings:
        $a = "execute"
        $b = "malicious_code"
      condition:
        $a and $b
    }
    
    ```
  或者是使用 Snort/Suricata Signature：

```

snort
alert tcp any any -> any 80 (msg:"Veeam Backup & Replication 遠端代碼執行漏洞"; content:"execute"; content:"malicious_code";)

```
* **緩解措施**: 更新 Veeam Backup & Replication 軟體到最新版本，或者是修改配置文件以禁用遠端代碼執行功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Remote Code Execution (RCE)**: 遠端代碼執行是一種攻擊技術，允許攻擊者在遠端伺服器上執行任意代碼。
* **Authenticated User**: 認證使用者是指已經通過身份驗證的使用者，可以訪問某些受限制的資源。
* **Buffer Overflow**: 緩衝區溢出是一種攻擊技術，允許攻擊者將任意代碼寫入緩衝區，從而執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/veeam-backup-replication-rce-flaw-lets.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


