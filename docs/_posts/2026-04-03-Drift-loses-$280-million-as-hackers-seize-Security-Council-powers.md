---
layout: post
title:  "Drift loses $280 million as hackers seize Security Council powers"
date:   2026-04-03 01:48:39 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Drift Protocol 攻擊：利用耐用Nonce賬戶和預簽名交易進行精心策劃的攻擊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Durable Nonce Accounts`, `Pre-Signed Transactions`, `Multisig Approvals`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Drift Protocol 的安全委員會管理權限被攻擊者利用耐用Nonce賬戶和預簽名交易進行攻擊。攻擊者沒有利用任何程式碼漏洞或智能合約漏洞，而是利用了系統的設計缺陷。
* **攻擊流程圖解**: 
    1. 攻擊者創建耐用Nonce賬戶。
    2. 攻擊者獲得 2/5 的多重簽名批准。
    3. 攻擊者預簽名惡意交易。
    4. 攻擊者執行合法交易並立即執行預簽名惡意交易。
    5. 攻擊者獲得管理權限並轉移資金。
* **受影響元件**: Drift Protocol 的安全委員會管理系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 2/5 的多重簽名批准。
* **Payload 建構邏輯**:

    ```
    
    python
    # 示例 Payload 結構
    payload = {
        "transaction": {
            "from": "attacker_address",
            "to": "victim_address",
            "value": "1000000"
        },
        "signature": "attacker_signature"
    }
    
    ```
    *範例指令*: 使用 `curl` 發送惡意交易。

```

bash
curl -X POST \
  https://drift-protocol.com/api/transactions \
  -H 'Content-Type: application/json' \
  -d '{"transaction": {"from": "attacker_address", "to": "victim_address", "value": "1000000"}, "signature": "attacker_signature"}'

```
* **繞過技術**: 攻擊者可以利用耐用Nonce賬戶和預簽名交易來繞過安全委員會的管理權限。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `attacker_hash` | `attacker_ip` | `attacker_domain` | `/attacker/file/path` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Drift_Protocol_Attack {
        meta:
            description = "Drift Protocol 攻擊偵測規則"
            author = "Your Name"
        strings:
            $payload = { 28 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
        condition:
            $payload at 0
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。

```

sql
index=drift_protocol sourcetype=transaction | search transaction.from="attacker_address" AND transaction.to="victim_address"

```
* **緩解措施**: 除了更新修補之外，還需要修改安全委員會的管理權限設定，例如增加多重簽名批准的門檻。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Durable Nonce Accounts (耐用Nonce賬戶)**: 想像一個可以重複使用的Nonce賬戶。技術上是指一個可以多次使用的Nonce賬戶，攻擊者可以利用這種賬戶來進行多次交易。
* **Pre-Signed Transactions (預簽名交易)**: 想像一個已經簽名的交易。技術上是指一個已經被簽名的交易，攻擊者可以利用這種交易來進行快速的攻擊。
* **Multisig Approvals (多重簽名批准)**: 想像一個需要多個簽名的批准。技術上是指一個需要多個簽名的批准，攻擊者需要獲得多個簽名才能進行攻擊。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/drift-loses-280-million-as-hackers-seize-security-council-powers/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


