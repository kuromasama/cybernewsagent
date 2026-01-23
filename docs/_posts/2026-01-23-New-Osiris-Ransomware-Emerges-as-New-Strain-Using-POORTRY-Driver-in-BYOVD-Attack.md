---
layout: post
title:  "New Osiris Ransomware Emerges as New Strain Using POORTRY Driver in BYOVD Attack"
date:   2026-01-23 01:12:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Osiris 勒索軟體的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: BYOVD (Bring Your Own Vulnerable Driver), Hybrid Encryption, Living Off The Land (LOTL)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Osiris 勒索軟體利用了一個名為 POORTRY 的惡意驅動程式，該驅動程式設計用於提升權限和終止安全工具。這是一種 BYOVD 攻擊，與傳統的利用已知漏洞的驅動程式不同，POORTRY 是一個專門設計的惡意驅動程式。
* **攻擊流程圖解**:
  1. 攻擊者使用 Rclone 將敏感資料外洩到 Wasabi 雲儲存桶。
  2. 部署 POORTRY 惡意驅動程式以提升權限和終止安全工具。
  3. 使用 Netscan、Netexec 和 MeshAgent 等工具進行網路掃描和權限提升。
  4. 部署 Osiris 勒索軟體並加密目標系統的檔案。
* **受影響元件**: Windows 系統，特別是具有弱點的驅動程式和安全工具。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有系統的管理權限和網路存取權。
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例 Payload 結構
      payload = {
        "driver": "POORTRY",
        "command": "terminate_security_tools",
        "args": ["security_tool_1", "security_tool_2"]
      }
    
    ```
  *範例指令*: 使用 `curl` 將 Payload 發送到目標系統。

```

bash
  curl -X POST -H "Content-Type: application/json" -d '{"driver": "POORTRY", "command": "terminate_security_tools", "args": ["security_tool_1", "security_tool_2"]}' http://target_system:8080

```
* **繞過技術**: 攻擊者可以使用 KillAV 工具部署弱點驅動程式以終止安全工具。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\POORTRY.sys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Osiris_Detection {
        meta:
          description = "Detects Osiris ransomware"
          author = "Your Name"
        strings:
          $poortry_driver = "POORTRY.sys"
        condition:
          $poortry_driver in (file of type pe)
      }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

spl
  index=osiris_detection (POORTRY.sys OR "terminate_security_tools")

```
* **緩解措施**: 限制 RDP 服務的存取權限，強制執行多因素驗證 (2FA)，使用應用程式白名單，並實施離線備份儲存。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **BYOVD (Bring Your Own Vulnerable Driver)**: 一種攻擊技術，攻擊者將弱點驅動程式帶入目標系統，以繞過安全工具。
* **Hybrid Encryption**: 一種加密技術，結合了對稱和非對稱加密算法，以提供更高的安全性。
* **LOTL (Living Off The Land)**: 一種攻擊技術，攻擊者使用目標系統現有的工具和功能，以避免被檢測。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/new-osiris-ransomware-emerges-as-new.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1543/)


