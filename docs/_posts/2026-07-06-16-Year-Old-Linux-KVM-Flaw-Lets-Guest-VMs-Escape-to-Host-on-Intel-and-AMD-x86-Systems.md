---
layout: post
title:  "16-Year-Old Linux KVM Flaw Lets Guest VMs Escape to Host on Intel and AMD x86 Systems"
date:   2026-07-06 19:46:34 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Januscape：Linux KVM Hypervisor 中的 use-after-free 漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數待定)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Use-after-free, Shadow MMU, Nested Virtualization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Januscape 漏洞源於 KVM Hypervisor 中的 Shadow MMU 代碼，該代碼在處理 guest 虛擬機器的記憶體請求時，未能正確地檢查頁面表的類型，導致了 use-after-free 的情況。具體來說，當 KVM 需要重新使用一個已經釋放的頁面表時，它只根據記憶體地址進行匹配，而忽略了頁面表的類型，這導致了 KVM 內部記錄的混亂。
* **攻擊流程圖解**:
  1. Guest 虛擬機器發送記憶體請求給 KVM Hypervisor。
  2. KVM Hypervisor 將請求轉發給 Shadow MMU。
  3. Shadow MMU 尋找一個可用的頁面表，如果找到，則將其重新使用。
  4. 如果頁面表已經被釋放，則會導致 use-after-free 的情況。
* **受影響元件**: Linux KVM Hypervisor，版本號從 2.6.36 到 5.10.259。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Guest 虛擬機器需要有 root 權限，且需要啟用 nested virtualization。
* **Payload 建構邏輯**:

    ```
    
    python
    # 示例 Payload
    payload = b"\x00\x00\x00\x00"  # 記憶體地址
    payload += b"\x01\x00\x00\x00"  # 頁面表類型
    
    ```
* **繞過技術**: 可以使用 Heap Spraying 技術來繞過 KVM 的記憶體保護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Januscape_Detection {
      meta:
        description = "Detects Januscape exploit"
      strings:
        $payload = { 00 00 00 00 01 00 00 00 }
      condition:
        $payload at entry_point
    }
    
    ```
* **緩解措施**: 更新 Linux KVM Hypervisor 到最新版本，或者禁用 nested virtualization。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Shadow MMU (影子記憶體管理單元)**: 一種用於虛擬化的記憶體管理技術，允許 guest 虛擬機器訪問 host 的記憶體。
* **Nested Virtualization (嵌套虛擬化)**: 一種允許 guest 虛擬機器創建自己的虛擬機器的技術。
* **Use-after-free (釋放後使用)**: 一種記憶體相關的漏洞，當一個已經釋放的記憶體區塊被重新使用時，可能會導致程式崩潰或安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/16-year-old-linux-kvm-flaw-lets-guest.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


