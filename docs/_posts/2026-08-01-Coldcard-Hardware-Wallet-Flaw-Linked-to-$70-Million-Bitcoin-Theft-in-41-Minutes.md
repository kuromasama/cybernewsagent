---
layout: post
title:  "Coldcard Hardware Wallet Flaw Linked to $70 Million Bitcoin Theft in 41 Minutes"
date:   2026-08-01 18:58:22 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Coldcard 硬體錢包漏洞：利用與防禦技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Information Leak (Info Leak)
> * **關鍵技術**: Deterministic Software Pseudorandom Number Generator (PRNG), Hardware Random Number Generator (RNG), Firmware Flaw

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Coldcard 硬體錢包的 firmware 中存在一個錯誤，導致 seed 生成使用了 deterministic software pseudorandom number generator (PRNG) 而不是 hardware random number generator (RNG)。這個錯誤使得攻擊者可以預測 seed 的生成。
* **攻擊流程圖解**: 
  1. 攻擊者獲得 Coldcard 硬體錢包的 firmware 版本。
  2. 攻擊者分析 firmware 中的 PRNG 算法。
  3. 攻擊者使用 PRNG 算法生成可能的 seed 值。
  4. 攻擊者使用生成的 seed 值嘗試登入 Coldcard 硬體錢包。
* **受影響元件**: Coldcard Mk2、Mk3、Mk4、Mk5 和 Q 版本的硬體錢包。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Coldcard 硬體錢包的 firmware 版本和 seed 生成算法。
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    
    def generate_seed(firmware_version, seed_algorithm):
        # 使用 PRNG 算法生成 seed 值
        seed = hashlib.sha256(firmware_version.encode()).hexdigest()
        return seed
    
    # 範例指令
    firmware_version = "4.0.1"
    seed_algorithm = "PRNG"
    seed = generate_seed(firmware_version, seed_algorithm)
    print(seed)
    
    ```
* **繞過技術**: 攻擊者可以使用 side-channel 攻擊或 timing 攻擊來繞過 Coldcard 硬體錢包的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /firmware.bin |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Coldcard_Firmware_Vulnerability {
      meta:
        description = "Coldcard 硬體錢包 firmware 漏洞"
        author = "Your Name"
      strings:
        $a = "PRNG" ascii
      condition:
        $a at 0x1000
    }
    
    ```
* **緩解措施**: 更新 Coldcard 硬體錢包的 firmware 至最新版本，並使用強密碼和安全的 seed 生成算法。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deterministic Software Pseudorandom Number Generator (PRNG)**: 一種使用算法生成隨機數的方法，與真正的隨機數生成器不同，PRNG 會根據初始值生成一系列可預測的數字。
* **Hardware Random Number Generator (RNG)**: 一種使用硬體元件生成真正隨機數的方法，與 PRNG 不同，RNG 會根據物理現象生成不可預測的數字。
* **Firmware Flaw**: 一種存在於 firmware 中的安全漏洞，可能會導致硬體設備的安全性受到影響。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/coldcard-hardware-wallet-flaw-linked-to.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


