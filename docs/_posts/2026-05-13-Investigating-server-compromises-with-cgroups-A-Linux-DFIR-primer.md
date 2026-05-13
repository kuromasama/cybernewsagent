---
layout: post
title:  "Investigating server compromises with cgroups: A Linux DFIR primer"
date:   2026-05-13 14:15:06 +0000
categories: [security]
severity: high
---

# 🔥 利用 Linux cgroup 進行威脅偵測與防禦繞過
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: cgroup, Linux Kernel, systemd

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Linux cgroup 是一個用於限制系統資源的機制，但它也可以被用於偵測和防禦威脅。然而，如果攻擊者可以創建和管理 cgroup，他們可以利用這個機制來繞過安全防禦。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個新的 cgroup
    2. 攻擊者將惡意程序添加到 cgroup 中
    3. 攻擊者利用 cgroup 的限制機制來隱藏惡意程序
* **受影響元件**: Linux Kernel 3.10 以上版本，systemd 215 以上版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 root 權限或可以創建 cgroup 的權限
* **Payload 建構邏輯**:

    ```
    
    bash
        # 創建一個新的 cgroup
        cgcreate -g cpu:/my_cgroup
        
        # 將惡意程序添加到 cgroup 中
        cgclassify -g cpu:/my_cgroup $PID
        
        # 利用 cgroup 的限制機制來隱藏惡意程序
        cgset -r cpu.shares=100 my_cgroup
    
    ```
* **繞過技術**: 攻擊者可以利用 cgroup 的限制機制來繞過安全防禦，例如利用 cgroup 的 cpu.shares 限制來隱藏惡意程序

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 描述 |
| --- | --- |
| cgcreate | 創建新的 cgroup |
| cgclassify | 將程序添加到 cgroup 中 |
| cgset | 設定 cgroup 的限制機制 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule cgroup_malicious {
            meta:
                description = "偵測惡意 cgroup"
            strings:
                $a = "cgcreate"
                $b = "cgclassify"
                $c = "cgset"
            condition:
                any of them
        }
    
    ```
* **緩解措施**: 限制 cgroup 的創建和管理權限，監控 cgroup 的活動，並設定 cgroup 的限制機制來防止惡意程序

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **cgroup (控制群組)**: 一個用於限制系統資源的機制
* **systemd (系統初始化)**: 一個用於初始化和管理系統服務的機制
* **Linux Kernel (Linux 核心)**: 操作系統的核心部分，負責管理硬件資源和提供系統服務

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://redcanary.com/blog/threat-detection/linux-cgroups/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/001/)


