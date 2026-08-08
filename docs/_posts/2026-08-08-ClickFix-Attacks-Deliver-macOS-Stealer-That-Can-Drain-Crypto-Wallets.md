---
layout: post
title:  "ClickFix Attacks Deliver macOS Stealer That Can Drain Crypto Wallets"
date:   2026-08-08 01:04:41 +0000
categories: [security]
severity: high
---

# 🔥 解析 ClickFix 式攻擊：Go 基礎的 macOS 惡意軟體與加密貨幣盜竊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: ClickFix 式攻擊、Go 基礎的 macOS 惡意軟體、加密貨幣盜竊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ClickFix 式攻擊利用 macOS 的 Terminal 應用程式，透過 Bash 腳本收集系統資訊，並下載相容的 macOS 惡意軟體。
* **攻擊流程圖解**:
  1. 使用者在 Terminal 中執行 ClickFix 命令。
  2. Bash 腳本收集系統資訊。
  3. 下載相容的 macOS 惡意軟體。
  4. 惡意軟體執行，盜竊加密貨幣資訊。
* **受影響元件**: macOS、Terminal、Bash

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: macOS 系統、Terminal 應用程式。
* **Payload 建構邏輯**:

    ```
    
    go
      package main
    
      import (
        "fmt"
        "os/exec"
      )
    
      func main() {
        // 收集系統資訊
        cmd := exec.Command("uname", "-a")
        output, err := cmd.CombinedOutput()
        if err != nil {
          fmt.Println(err)
        }
        fmt.Println(string(output))
    
        // 下載相容的 macOS 惡意軟體
        // ...
      }
    
    ```
* **繞過技術**: 使用 ClickFix 式攻擊，透過 Bash 腳本收集系統資訊，下載相容的 macOS 惡意軟體。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ClickFix_Attack {
        meta:
          description = "ClickFix 式攻擊"
          author = "..."
        strings:
          $a = "ClickFix"
        condition:
          $a
      }
    
    ```
* **緩解措施**: 更新 macOS 系統、Terminal 應用程式，使用安全的 Bash 腳本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix 式攻擊**: 一種透過 ClickFix 命令，收集系統資訊，下載相容的 macOS 惡意軟體的攻擊方式。
* **Go 基礎的 macOS 惡意軟體**: 一種使用 Go 語言開發的 macOS 惡意軟體，能夠盜竊加密貨幣資訊。
* **加密貨幣盜竊**: 一種透過惡意軟體，盜竊加密貨幣資訊的行為。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/clickfix-attacks-deliver-macos-stealer.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


