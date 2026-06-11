---
layout: post
title:  "New Attacks Trick OpenClaw AI Agent Into Running Code and Leaking Secrets"
date:   2026-06-11 20:12:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 OpenClaw AI 代理的安全漏洞：利用和防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0)
> * **受駭指標**: 遠程代碼執行 (RCE) 和敏感數據洩露
> * **關鍵技術**: Prompt Injection、Agent Phishing、Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OpenClaw AI 代理的安全漏洞源於其處理用戶輸入的方式。當用戶傳遞一個共享聯繫人、vCard 或位置標籤時，代理會將這些數據扁平化並傳遞給模型，沒有進行適當的邊界檢查和驗證。
* **攻擊流程圖解**:
  1. 攻擊者創建一個包含惡意代碼的共享聯繫人或 vCard。
  2. 攻擊者將惡意聯繫人或 vCard 傳遞給 OpenClaw 代理。
  3. 代理將惡意代碼扁平化並傳遞給模型。
  4. 模型執行惡意代碼，導致遠程代碼執行或敏感數據洩露。
* **受影響元件**: OpenClaw 代理版本 2026.4.23 之前。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個包含惡意代碼的共享聯繫人或 vCard。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例惡意代碼
    payload = "<contact: name, number>"
    payload += "rm -rf /"
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術來避免被檢測，例如使用 Base64 編碼或使用其他格式的惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malicious_code |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OpenClaw_Malicious_Code {
      meta:
        description = "Detects malicious code in OpenClaw 代理"
      strings:
        $a = "<contact: name, number>"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 更新 OpenClaw 代理版本至 2026.4.23 或更高版本，並實施適當的安全配置和驗證機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Prompt Injection**: 一種安全漏洞，允許攻擊者注入惡意代碼到用戶輸入中。
* **Agent Phishing**: 一種社會工程攻擊，利用代理的信任機制來獲取敏感數據。
* **Deserialization**: 一種程序，將序列化的數據轉換回原始格式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


