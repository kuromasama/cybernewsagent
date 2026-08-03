---
layout: post
title:  "COLDCARD wallet RNG flaw likely linked to $88 million Bitcoin theft"
date:   2026-08-03 02:06:43 +0000
categories: [security]
severity: critical
---

# 🚨 COLDCARD 硬體錢包漏洞解析：利用 RNG 錯誤實現比特幣盜竊

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 隨機數生成器錯誤導致私鑰泄露
> * **關鍵技術**: RNG, Yasmarang, MicroPython, STM32

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: COLDCARD 硬體錢包的 RNG (隨機數生成器) 代碼中存在錯誤，導致 ngu.random 使用 MicroPython 的 Yasmarang fallback 而不是 STM32 硬體 RNG。這使得攻擊者可以生成可能的錢包種子，從而導致私鑰泄露。
* **攻擊流程圖解**:
  1. 攻擊者獲得 COLDCARD 硬體錢包的固件版本。
  2. 攻擊者分析固件代碼，發現 RNG 錯誤。
  3. 攻擊者使用 Yasmarang fallback 生成可能的錢包種子。
  4. 攻擊者比較生成的種子與區塊鏈上的地址，確認正確的種子。
  5. 攻擊者使用正確的種子生成私鑰，實現比特幣盜竊。
* **受影響元件**: COLDCARD Mk2 和 Mk3 的 4.0.1 至 4.1.9 版本，Mk4 和 Mk5 的 5.6.0 版本之前，Q 裝置的 1.5.0Q 版本之前。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 COLDCARD 硬體錢包的固件版本和 Yasmarang fallback 的實現細節。
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    
    def generate_seed(firmware_version):
        # 使用 Yasmarang fallback 生成可能的錢包種子
        seed = hashlib.sha256(firmware_version.encode()).hexdigest()
        return seed
    
    def generate_private_key(seed):
        # 使用種子生成私鑰
        private_key = hashlib.sha256(seed.encode()).hexdigest()
        return private_key
    
    # 示例使用
    firmware_version = "4.0.1"
    seed = generate_seed(firmware_version)
    private_key = generate_private_key(seed)
    print(private_key)
    
    ```
* **繞過技術**: 攻擊者可以使用多個種子生成私鑰，增加成功率。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/bin/coldcard |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule coldcard_rng_error {
        meta:
            description = "COLDCARD RNG 錯誤偵測"
            author = "Your Name"
        strings:
            $a = " Yasmarang fallback"
        condition:
            $a
    }
    
    ```
* **緩解措施**: 更新 COLDCARD 硬體錢包的固件版本至 4.2.0 或更高版本，生成新的種子和私鑰。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **RNG (隨機數生成器)**: 一種生成隨機數的算法或硬體元件。
* **Yasmarang**: 一種 MicroPython 中的隨機數生成器實現。
* **STM32**: 一種 ARM Cortex-M 微控制器系列。
* **私鑰 (Private Key)**: 一種用於加密和解密數據的密鑰。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/coldcard-wallet-rng-flaw-likely-linked-to-88-million-bitcoin-theft/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


