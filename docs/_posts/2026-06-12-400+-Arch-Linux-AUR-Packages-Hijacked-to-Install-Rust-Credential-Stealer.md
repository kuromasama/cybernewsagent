---
layout: post
title:  "400+ Arch Linux AUR Packages Hijacked to Install Rust Credential Stealer"
date:   2026-06-12 19:58:52 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Arch Linux AUR 包管理器的供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 8.7)
> * **受駭指標**: 供應鏈攻擊，導致 RCE (Remote Code Execution)
> * **關鍵技術**: eBPF (Extended Berkeley Packet Filter), Rust, npm

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Arch Linux AUR 包管理器的信任模型，採用了 400 多個包，並修改了其 build 腳本以安裝一個憑證竊取器。
* **攻擊流程圖解**:
  1. 攻擊者採用了 AUR 包管理器中的包。
  2. 攻擊者修改了包的 build 腳本以安裝一個憑證竊取器。
  3. 用戶安裝或更新包時，build 腳本會執行，安裝憑證竊取器。
* **受影響元件**: Arch Linux AUR 包管理器，npm 包 atomic-lockfile@1.4.2

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要採用 AUR 包管理器中的包，並修改其 build 腳本。
* **Payload 建構邏輯**:

    ```
    
    rust
      // deps payload
      use std::fs;
      use std::io;
      use std::path::Path;
    
      fn main() {
        // 收集憑證和敏感信息
        let cookies = get_cookies();
        let tokens = get_tokens();
        let ssh_keys = get_ssh_keys();
    
        // 上傳收集到的信息到遠程服務器
        upload_info(cookies, tokens, ssh_keys);
      }
    
    ```
  *範例指令*: `npm install atomic-lockfile@1.4.2`
* **繞過技術**: 攻擊者使用 eBPF 根kit 來隱藏其進程和 socket。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b |  |  | /var/lib/ |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule atomic_lockfile {
        meta:
          description = "Detects atomic-lockfile payload"
          author = "Your Name"
        strings:
          $a = "atomic-lockfile"
          $b = "deps"
        condition:
          $a and $b
      }
    
    ```
  *或者是具體的 SIEM 查詢語法 (Splunk/Elastic)*: `index=your_index (atomic-lockfile OR deps)`
* **緩解措施**: 刪除受影響的包，重新安裝系統，並更新包管理器。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 內核技術，允許用戶空間程序注入和執行內核代碼。
* **Rust**: 一種系統編程語言，注重安全性和性能。
* **npm (Node Package Manager)**: 一種 Node.js 包管理器，允許用戶安裝和管理包。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/400-arch-linux-aur-packages-hijacked-to.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


