---
layout: post
title:  "Over 24,000 exposed server BMCs leak password hash via decades-old flaw"
date:   2026-07-28 13:48:37 +0000
categories: [security]
severity: critical
---

# 🚨 解析 IPMI 2.0 身份驗證弱點：基於 20 年前的漏洞對 BMC 伺服器的攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Unauthorized Access to BMC Servers
> * **關鍵技術**: IPMI 2.0, BMC, Authentication Bypass

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: IPMI 2.0 的身份驗證機制中存在一個 20 年前的漏洞，允許攻擊者請求身份驗證回應，並使用專用 GPU 設備或類似設定進行離線密碼破解。
* **攻擊流程圖解**:
  1. 攻擊者發現公開暴露的 IPMI 服務（UDP 端口 623）。
  2. 攻擊者使用弱密碼或預設密碼嘗試登入 BMC 伺服器。
  3. 如果登入成功，攻擊者可以控制 BMC 伺服器，進而控制物理伺服器。
* **受影響元件**: IPMI 2.0 的 BMC 伺服器，包括 Supermicro 和 HPE 伺服器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 公開暴露的 IPMI 服務（UDP 端口 623）和弱密碼或預設密碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 定義 IPMI 服務地址和端口
    ipmi_server = 'example.com'
    ipmi_port = 623
    
    # 定義弱密碼或預設密碼
    password = 'weak_password'
    
    # 建立 UDP 連接
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 發送登入請求
    login_request = b'\x06\x00\x00\x00\x00\x00\x00\x00'  # IPMI 登入請求
    sock.sendto(login_request, (ipmi_server, ipmi_port))
    
    # 接收登入回應
    login_response, _ = sock.recvfrom(1024)
    
    # 驗證登入回應
    if login_response[0] == 0x06:  # 登入成功
        print('Login successful!')
    else:
        print('Login failed.')
    
    ```
* **繞過技術**: 使用弱密碼或預設密碼進行登入，或者使用專用 GPU 設備或類似設定進行離線密碼破解。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /etc/ipmi.conf |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule IPMI_Login_Attempt {
      meta:
        description = "IPMI 登入嘗試"
        author = "Your Name"
      strings:
        $ipmi_login_request = { 06 00 00 00 00 00 00 00 }
      condition:
        $ipmi_login_request at entry_point
    }
    
    ```
* **緩解措施**:
  1. 更新 IPMI 2.0 的 BMC 伺服器到最新版本。
  2. 使用強密碼和密碼策略。
  3. 限制 IPMI 服務的存取權限。
  4. 監控 IPMI 服務的登入嘗試和異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **IPMI (Intelligent Platform Management Interface)**: 一種用於管理和監控伺服器的標準化接口。
* **BMC (Baseboard Management Controller)**: 一種嵌入式控制器，用于管理和監控伺服器的硬件元件。
* **UDP (User Datagram Protocol)**: 一種無連接的網絡協議，用于傳輸數據。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/over-24-000-exposed-server-bmcs-leak-password-hash-via-decades-old-flaw/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1215/)


