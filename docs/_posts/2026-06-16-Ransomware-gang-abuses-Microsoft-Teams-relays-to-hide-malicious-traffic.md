---
layout: post
title:  "Ransomware gang abuses Microsoft Teams relays to hide malicious traffic"
date:   2026-06-16 11:00:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 DragonForce 勒索軟體的 Microsoft Teams TURN Relay 滲透技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: TURN Relay, Microsoft Teams, Go-based Malware, BYOVD (Bring Your Own Vulnerable Driver)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: DragonForce 勒索軟體利用 Microsoft Teams 的 TURN (Traversal Using Relays around NAT) Relay 伺服器來隱藏其命令和控制 (C2) 流量。這是因為 TURN Relay 伺服器被設計用來允許 Microsoft Teams 用戶在 NAT (Network Address Translation) 後面的網路中進行通訊。
* **攻擊流程圖解**:
  1. 攻擊者首先利用未知的 SQL 或 MSSQL 伺服器漏洞取得系統存取權。
  2. 下載並執行 ZIP 檔案，包含 VirtualBox/DbgView 執行檔和惡意 DLL 檔案。
  3. 利用 BYOVD 技術，攻擊者使用多個漏洞驅動程式（如 Huawei 的 HWAuidoOs2Ec.sys）來取得核心級別的存取權。
  4. 部署 Backdoor.Turn 惡意軟體，該軟體會使用 Microsoft Teams TURN Relay 伺服器來隱藏其 C2 流量。
* **受影響元件**: Microsoft Teams、SQL/MSSQL 伺服器、多個漏洞驅動程式（如 Huawei 的 HWAuidoOs2Ec.sys）。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有系統存取權和能夠下載並執行檔案的權限。
* **Payload 建構邏輯**:

    ```
    
    go
      // Go-based Malware Payload
      package main
    
      import (
        "fmt"
        "net/http"
      )
    
      func main() {
        // 使用 Microsoft Teams TURN Relay 伺服器來隱藏 C2 流量
        url := "https://example.com/turn-relay"
        resp, err := http.Get(url)
        if err != nil {
          fmt.Println(err)
        } else {
          fmt.Println(resp.Status)
        }
      }
    
    ```
  *範例指令*: `curl -X GET "https://example.com/turn-relay" -H "User-Agent: Mozilla/5.0"`
* **繞過技術**: 攻擊者可以使用 BYOVD 技術來繞過安全工具和防火牆。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXXXXXX | 192.168.1.100 | example.com | C:\Windows\Temp\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Backdoor_Turn {
        meta:
          description = "Detects Backdoor.Turn malware"
          author = "Your Name"
        strings:
          $a = "https://example.com/turn-relay"
        condition:
          $a in (http.request.uri)
      }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
  index=web_logs | search https://example.com/turn-relay

```
* **緩解措施**: 更新系統和應用程式，關閉不必要的服務，使用防火牆和入侵偵測系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TURN (Traversal Using Relays around NAT)**: TURN 是一個允許用戶在 NAT 後面的網路中進行通訊的協議。它使用中繼伺服器來轉發流量。
* **BYOVD (Bring Your Own Vulnerable Driver)**: BYOVD 是一種攻擊技術，攻擊者使用漏洞驅動程式來取得核心級別的存取權。
* **Microsoft Teams TURN Relay**: Microsoft Teams TURN Relay 是一個允許用戶在 NAT 後面的網路中進行通訊的伺服器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


