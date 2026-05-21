---
layout: post
title:  "9-Year-Old Linux Kernel Flaw Enables Root Command Execution on Major Distros"
date:   2026-05-21 09:25:26 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Linux Kernel 9 年隱患：CVE-2026-46333 利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數: 5.5)
> * **受駭指標**: Local Privilege Escalation (LPE)
> * **關鍵技術**: `__ptrace_may_access()`, `ssh-keysign`, `pkexec`, `accounts-daemon`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 Linux Kernel 的 `__ptrace_may_access()` 函數中，未正確管理權限，導致未經授權的本地使用者可以存取敏感檔案和執行任意命令。
* **攻擊流程圖解**:
  1. 攻擊者獲得本地使用者權限
  2. 利用 `ssh-keysign`、`pkexec` 或 `accounts-daemon` 等工具，繞過權限限制
  3. 存取敏感檔案（如 `/etc/shadow` 和 `/etc/ssh/*_key`）
  4. 執行任意命令以 root 權限
* **受影響元件**: Linux Kernel 4.15 至 5.15 版本，包括 Debian、Fedora 和 Ubuntu 等主要發行版

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 本地使用者權限
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import os
      import subprocess
    
      # 利用 ssh-keysign 繞過權限限制
      subprocess.run(['ssh-keysign', '-f', '/etc/ssh/ssh_host_rsa_key'])
    
      # 存取敏感檔案
      with open('/etc/shadow', 'r') as f:
          print(f.read())
    
      # 執行任意命令
      subprocess.run(['pkexec', 'bash'])
    
    ```
* **繞過技術**: 利用 `kernel.yama.ptrace_scope` 設定為 2，暫時繞過權限限制

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | `/etc/shadow` |
|  |  |  | `/etc/ssh/*_key` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Linux_Kernel_Vuln {
        meta:
          description = "Linux Kernel 9 年隱患 CVE-2026-46333"
          author = "Your Name"
        strings:
          $a = "__ptrace_may_access"
        condition:
          $a
      }
    
    ```
* **緩解措施**: 更新 Linux Kernel 至最新版本，或暫時設定 `kernel.yama.ptrace_scope` 為 2

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **`__ptrace_may_access()`**: 一個 Linux Kernel 函數，負責管理進程間的存取權限。
* **`ssh-keysign`**: 一個工具，負責簽署 SSH 金鑰。
* **`pkexec`**: 一個工具，負責以 root 權限執行命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/9-year-old-linux-kernel-flaw-enables.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


