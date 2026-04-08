---
layout: post
title:  "Iran-Linked Hackers Disrupt U.S. Critical Infrastructure by Targeting Internet-Exposed PLCs"
date:   2026-04-08 07:09:49 +0000
categories: [security]
severity: critical
---

# 🚨 解析伊朗駭客對美國關鍵基礎設施的攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠端程式碼執行 (RCE) 和資料操控
> * **關鍵技術**: PLC (Programmable Logic Controller) 漏洞利用、SSH 連線、Dropbear 軟體

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 伊朗駭客利用 Rockwell Automation 和 Allen-Bradley PLC 裝置的漏洞，進行遠端程式碼執行和資料操控。
* **攻擊流程圖解**:
  1. 駭客首先使用第三方主機的配置軟體（如 Rockwell Automation 的 Studio 5000 Logix Designer）建立與受害者 PLC 的連線。
  2. 然後，駭客部署 Dropbear 軟體，建立 SSH 連線，從而實現遠端存取和資料操控。
* **受影響元件**: Rockwell Automation CompactLogix 和 Micro850 PLC 裝置。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客需要有受害者 PLC 的 IP 地址和配置軟體的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import paramiko
    
    # 建立 SSH 連線
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('plc_ip', username='username', password='password')
    
    # 執行遠端命令
    stdin, stdout, stderr = ssh.exec_command('command')
    
    # 關閉 SSH 連線
    ssh.close()
    
    ```
* **繞過技術**: 駭客可以使用 VPN 或代理伺服器來隱藏其 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 192.0.2.1 |
| Domain | example.com |
| File Path | /path/to/malware |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PLC_Malware {
      meta:
        description = "PLC Malware Detection"
      strings:
        $a = "malware_string"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 將 PLC 裝置更新到最新版本，使用強密碼和多因素驗證，限制 PLC 的網路存取，並監控 PLC 的異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PLC (Programmable Logic Controller)**: 一種可編程的邏輯控制器，用于控制和監控工業設備。
* **Dropbear**: 一種輕量級的 SSH 伺服器軟體。
* **SSH (Secure Shell)**: 一種安全的遠端存取協議。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/iran-linked-hackers-disrupt-us-critical.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


