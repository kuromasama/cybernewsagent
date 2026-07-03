---
layout: post
title:  "PamStealer Uses Fake Maccy Sites and PAM Checks to Steal Mac Login Passwords"
date:   2026-07-03 08:52:27 +0000
categories: [security]
severity: high
---

# 🔥 解析 PamStealer：一種針對 macOS 的資訊竊取者
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: Info Leak
> * **關鍵技術**: AppleScript, Rust, PAM, Gatekeeper 繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PamStealer 利用 AppleScript 的特性，通過自我複製和修改來繞過 Gatekeeper 的檢查。攻擊者創建了一個假的 Maccy 網站，提供一個帶有惡意 AppleScript 的磁碟映像檔。
* **攻擊流程圖解**:
  1. 使用者下載並開啟磁碟映像檔。
  2. AppleScript 被執行，下載並安裝 Rust-based 的資訊竊取者。
  3. 資訊竊取者收集使用者的敏感資料，包括密碼、瀏覽器資料和剪貼板內容。
  4. 資訊竊取者通過 PAM 驗證使用者的密碼。
* **受影響元件**: macOS (所有版本)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要下載並開啟磁碟映像檔。
* **Payload 建構邏輯**:

    ```
    
    rust
    // Rust-based 資訊竊取者
    use std::fs::File;
    use std::io::Read;
    
    fn main() {
        // 收集使用者的敏感資料
        let mut file = File::open("/Users/username/Library/Application Support/Maccy/clipboard.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        println!("{}", contents);
    }
    
    ```
* **繞過技術**: PamStealer 利用 AppleScript 的特性，通過自我複製和修改來繞過 Gatekeeper 的檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | maccyapp.com | /Users/username/Library/Application Support/Maccy/clipboard.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PamStealer {
      meta:
        description = "PamStealer 資訊竊取者"
        author = "Your Name"
      strings:
        $a = "Maccy.scpt"
        $b = "clipboard.txt"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 使用者應該避免下載並開啟來自未知來源的磁碟映像檔。系統管理員應該設定 Gatekeeper 來阻止未知來源的應用程式。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AppleScript**: 一種腳本語言，用于自動化 macOS 的任務。
* **PAM (Pluggable Authentication Modules)**: 一種驗證模組，用于驗證使用者的密碼。
* **Gatekeeper**: 一種安全功能，用于阻止未知來源的應用程式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


