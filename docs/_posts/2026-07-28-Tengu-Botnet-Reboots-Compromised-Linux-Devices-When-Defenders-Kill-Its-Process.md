---
layout: post
title:  "Tengu Botnet Reboots Compromised Linux Devices When Defenders Kill Its Process"
date:   2026-07-28 19:12:33 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Tengu Botnet：利用 Linux watchdog 重新啟動和自我防禦機制

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Hardware Watchdog`, `Systemd Service`, `ELF Header Manipulation`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Tengu Botnet 利用 Linux watchdog 機制重新啟動受感染的設備。當主進程被終止時，watchdog 會在約 30 秒後重新啟動設備，允許 Tengu 的其他持續機制重新啟動惡意程式。
* **攻擊流程圖解**:
  1. Tengu Botnet 通过 Telnet 認證暴力破解攻擊 Linux 設備。
  2. 一旦攻擊成功，Tengu 會下載和安裝惡意程式。
  3. 惡意程式會 fork 一個守護進程，負責監視主進程的狀態。
  4. 如果主進程被終止，守護進程會重新啟動惡意程式。
* **受影響元件**: Linux 設備，尤其是那些具有 watchdog 機制的設備。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道目標設備的 Telnet 認證資訊。
* **Payload 建構邏輯**:

    ```
    
    python
      # Tengu Botnet Payload 結構
      payload = {
        'type': 'ELF',
        'data': '...'  # ELF 文件內容
      }
    
    ```
  *範例指令*:

```

bash
  curl -X POST -H "Content-Type: application/json" -d '{"type": "ELF", "data": "..."}' http://example.com/upload

```
* **繞過技術**: Tengu Botnet 可以通過修改 ELF Header 來繞過一些安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | 64.89.163.8 | ... | /tmp/tengu |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Tengu_Botnet {
        meta:
          description = "Tengu Botnet Malware"
          author = "..."
        strings:
          $elf_header = { 7f 45 4c 46 }
        condition:
          $elf_header at 0
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
      index=linux_logs (eventtype=telnet_login OR eventtype=elf_file_access)
    
    ```
* **緩解措施**: 除了更新修補之外，還需要關閉不必要的 Telnet 服務，修改默認認證資訊，並監視設備的 watchdog 機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Hardware Watchdog**: 一種硬件機制，用于監視系統的運行狀態，如果系統出現故障或崩潰，watchdog 會重新啟動系統。
* **Systemd Service**: 一種 Linux 服務管理機制，用于管理和控制系統服務的啟動和停止。
* **ELF Header Manipulation**: 一種技術，用于修改 ELF 文件的 header 信息，以繞過安全檢查或實現其他惡意目的。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/tengu-botnet-reboots-compromised-linux.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1543/)


