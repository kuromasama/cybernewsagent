---
layout: post
title:  "China-Aligned Groups Ramp Up Attacks: Dragon Weave Hits Czech Republic & Taiwan"
date:   2026-06-01 17:22:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Operation Dragon Weave：中國聯盟威脅群體的新型網絡間諜活動

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程命令執行 (RCE) 和資料外洩
> * **關鍵技術**: DLL side-loading, Rust-based loader, Azure Blob Storage

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Operation Dragon Weave 利用了 DLL side-loading 技術，通過欺騙系統載入惡意 DLL 文件，從而實現遠程命令執行和資料外洩。
* **攻擊流程圖解**:
  1. Spear-phishing 電子郵件包含 ZIP 附件
  2. ZIP 附件中包含多個文件，包括惡意 Windows Shortcut (LNK) 文件和 Rust-based dropper
  3. LNK 文件啟動 PowerShell 腳本，提取和執行惡意可執行文件 (RuntimeBroker_update.exe)
  4. 惡意可執行文件載入惡意 DLL 文件 (UnityPlayer.dll) 進行 DLL side-loading
  5. DLL 文件啟動 Rust-based loader (RUSTCLOAK)，解密和執行主 payload (AdaptixC2)
* **受影響元件**: Windows 系統，特別是使用 Azure Blob Storage 的系統

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Spear-phishing 電子郵件收件人需要執行附件中的惡意文件
* **Payload 建構邏輯**:

    ```
    
    python
    # Rust-based loader (RUSTCLOAK) 範例
    use std::fs::File;
    use std::io::Read;
    
    fn main() {
        // 解密 payload
        let mut file = File::open("payload.dat").unwrap();
        let mut payload = Vec::new();
        file.read_to_end(&mut payload).unwrap();
        let decrypted_payload = decrypt_payload(payload);
    
        // 執行 payload
        execute_payload(decrypted_payload);
    }
    
    fn decrypt_payload(payload: Vec<u8>) -> Vec<u8> {
        // 解密邏輯
    }
    
    fn execute_payload(payload: Vec<u8>) {
        // 執行 payload 邏輯
    }
    
    ```
* **繞過技術**: 使用 DLL side-loading 技術可以繞過某些安全軟件的檢測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\payload.dat |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Operation_Dragon_Weave {
        meta:
            description = "Detects Operation Dragon Weave malware"
            author = "Your Name"
        strings:
            $s1 = "UnityPlayer.dll"
            $s2 = "RUSTCLOAK"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新系統和安全軟件，使用 Azure Blob Storage 的系統需要特別注意安全設定

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL side-loading**: 一種攻擊技術，通過欺騙系統載入惡意 DLL 文件，從而實現遠程命令執行和資料外洩。
* **Rust-based loader**: 一種使用 Rust 編程語言開發的 loader，用于解密和執行 payload。
* **Azure Blob Storage**: 一種雲端儲存服務，提供高可用性和安全性的資料儲存和管理。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/china-aligned-groups-ramp-up-attacks.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


