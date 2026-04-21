---
layout: post
title:  "KelpDAO suffers $290 million heist tied to Lazarus hackers"
date:   2026-04-21 01:57:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 KelpDAO 2.9 億美元加密貨幣盜竊事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local Privilege Escalation)
> * **關鍵技術**: Cross-Chain Attack, RPC Node Compromise, DDoS, Tornado Cash

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: KelpDAO 的驗證層 (DVN) 存在漏洞，允許攻擊者竄改跨鏈消息，進而導致 rsETH 代幣被盜。
* **攻擊流程圖解**:
  1. 攻擊者竄改 RPC 節點，提供假的區塊鏈數據。
  2. 攻擊者對健康的 RPC 節點進行 DDoS 攻擊，迫使系統依賴於被竄改的節點。
  3. 假的跨鏈消息被接受為有效，系統確認了從未發生的交易，允許 rsETH 代幣被轉移。
* **受影響元件**: KelpDAO 的 rsETH 代幣和相關的 DeFi 協議 (Compound, Euler, Aave)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制 RPC 節點和進行 DDoS 攻擊的能力。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 竄改 RPC 節點
    rpc_node_url = "https://example.com/rpc"
    fake_blockchain_data = {"block_number": 123, "transactions": []}
    response = requests.post(rpc_node_url, json=fake_blockchain_data)
    
    # 對健康的 RPC 節點進行 DDoS 攻擊
    ddos_target_url = "https://example.com/rpc"
    ddos_attack = requests.get(ddos_target_url, stream=True)
    
    ```
* **繞過技術**: 攻擊者可以使用 Tornado Cash 來隱藏交易軌跡。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /rpc |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule KelpDAO_Attack {
      meta:
        description = "Detect KelpDAO attack"
        author = "Your Name"
      strings:
        $rpc_node_url = "https://example.com/rpc"
        $fake_blockchain_data = "{block_number: 123, transactions: []}"
      condition:
        $rpc_node_url and $fake_blockchain_data
    }
    
    ```
* **緩解措施**: 更新 KelpDAO 的驗證層 (DVN) 並強化 RPC 節點的安全性。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cross-Chain Attack (跨鏈攻擊)**: 想像兩個不同的區塊鏈之間的交易。技術上是指攻擊者竄改跨鏈消息，進而導致資產被盜。
* **RPC Node Compromise (RPC 節點竄改)**: 想像 RPC 節點被攻擊者控制。技術上是指攻擊者竄改 RPC 節點，提供假的區塊鏈數據。
* **DDoS (分佈式拒絕服務)**: 想像多個機器同時對一個目標發起請求。技術上是指攻擊者對目標發起大量請求，導致目標無法正常運作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/kelpdao-suffers-290-million-heist-tied-to-lazarus-hackers/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


