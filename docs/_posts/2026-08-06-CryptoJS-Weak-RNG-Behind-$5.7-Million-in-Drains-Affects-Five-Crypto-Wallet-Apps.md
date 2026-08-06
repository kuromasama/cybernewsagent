---
layout: post
title:  "CryptoJS Weak RNG Behind $5.7 Million in Drains Affects Five Crypto Wallet Apps"
date:   2026-08-06 13:47:53 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CryptoJS.lib.WordArray.random() 弱隨機數生成器漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 9.0)
> * **受駭指標**: Recovery Phrase 獲取漏洞
> * **關鍵技術**: Weak Random Number Generator, Entropy, Cryptography

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CryptoJS.lib.WordArray.random() 函數使用了弱隨機數生成器，導致生成的 entropy 過低，影響了使用此函數生成 recovery phrase 的錢包應用。
* **攻擊流程圖解**: 
  1. 攻擊者獲取弱隨機數生成器生成的 recovery phrase。
  2. 攻擊者使用枚舉法（enumeration）猜測 recovery phrase。
  3. 攻擊者使用猜測到的 recovery phrase 獲取用戶的加密貨幣。
* **受影響元件**: CryptoJS 版本低於 4.0.0，RRWallet、Bexo Wallet、NanChat、Bitcoin Libre、Milo 等錢包應用。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲取弱隨機數生成器生成的 recovery phrase。
* **Payload 建構邏輯**:

    ```
    
    python
    import itertools
    
    # 獲取弱隨機數生成器生成的 recovery phrase
    weak_recovery_phrase = "weak_recovery_phrase"
    
    # 使用枚舉法猜測 recovery phrase
    for phrase in itertools.product("abcdefghijklmnopqrstuvwxyz", repeat=12):
        if phrase == weak_recovery_phrase:
            print("Guessing recovery phrase:", phrase)
            break
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術來避免被檢測，例如使用代理伺服器、VPN 等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `sha256:weak_recovery_phrase` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `/path/to/weak/recovery/phrase` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule weak_recovery_phrase {
        meta:
            description = "Detect weak recovery phrase"
            author = "Your Name"
        strings:
            $weak_recovery_phrase = "weak_recovery_phrase"
        condition:
            $weak_recovery_phrase
    }
    
    ```
* **緩解措施**: 更新 CryptoJS 版本至 4.0.0 或以上，使用強隨機數生成器生成 recovery phrase。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Entropy (熵)**: 熵是指一個系統的隨機性或不確定性。高熵表示系統的隨機性高，低熵表示系統的隨機性低。
* **Weak Random Number Generator (弱隨機數生成器)**: 弱隨機數生成器是指生成的隨機數不夠隨機，容易被猜測或枚舉。
* **Recovery Phrase (恢復短語)**: 恢復短語是一種用於恢復加密貨幣的短語，通常由 12 個單詞組成。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/cryptojs-weak-rng-behind-57-million-in.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


