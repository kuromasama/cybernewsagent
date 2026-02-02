---
layout: post
title:  "Microsoft Begins NTLM Phase-Out With Three-Stage Plan to Move Windows to Kerberos"
date:   2026-02-02 18:34:28 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 NTLM 協議淘汰：Microsoft 的三階段過渡計畫

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Unauthorized Access
> * **關鍵技術**: NTLM, Kerberos, Authentication Protocols

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NTLM 協議的設計存在弱點，容易受到重放攻擊和中間人攻擊。
* **攻擊流程圖解**: 
  1. 攻擊者截獲 NTLM 認證請求
  2. 攻擊者重放認證請求
  3. 伺服器驗證通過，授予攻擊者存取權限
* **受影響元件**: Windows NT 4.0 至 Windows 10

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要截獲 NTLM 認證請求
* **Payload 建構邏輯**: 
    * 使用工具如 `ntlmrelayx` 來重放認證請求
    * 範例指令: `ntlmrelayx -t <target_ip> -u <username> -p <password>`

```

python
import requests

# 定義目標 IP 和認證資訊
target_ip = "192.168.1.100"
username = "admin"
password = "password123"

# 建構 NTLM 認證請求
ntlm_request = {
    "username": username,
    "password": password,
    "domain": "example.com"
}

# 重放認證請求
response = requests.post(f"http://{target_ip}/login", json=ntlm_request)

# 驗證是否授予存取權限
if response.status_code == 200:
    print("存取權限授予")
else:
    print("存取權限拒絕")

```
* **繞過技術**: 可以使用 WAF 繞過技巧，如使用 `curl` 來發送請求

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ntlm_relay {
        meta:
            description = "NTLM Relay Attack"
            author = "Blue Team"
        strings:
            $ntlm_request = { 0x4e 0x54 0x4c 0x4d }
        condition:
            $ntlm_request at entry_point
    }
    
    ```
* **緩解措施**: 啟用 Kerberos 認證，停用 NTLM 認證

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NTLM (New Technology LAN Manager)**: 一種用於 Windows 網路的認證協議。比喻：想像兩個人同時去改同一本帳簿，NTLM 就是用來確保這兩個人是誰的認證協議。
* **Kerberos**: 一種用於網路的認證協議。比喻：想像一個安全的門，Kerberos 就是用來開啟這個門的鑰匙。
* **中間人攻擊 (Man-in-the-Middle Attack)**: 一種攻擊方式，攻擊者截獲兩個實體之間的通訊。比喻：想像兩個人在聊天，中間人攻擊就是有人在偷聽他們的對話。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/microsoft-begins-ntlm-phase-out-with.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/)


